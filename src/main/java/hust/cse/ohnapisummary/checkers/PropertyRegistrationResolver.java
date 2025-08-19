package hust.cse.ohnapisummary.checkers;

import com.bai.env.*;
import com.bai.env.region.RegionBase;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import hust.cse.ohnapisummary.mapping.NAPIDescriptor;
import hust.cse.ohnapisummary.util.MyGlobalState;
import com.bai.checkers.CheckerBase;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 属性注册解析器 - 处理 napi_define_properties 调用
 */
class PropertyRegistrationResolver {
    
    // 存储解析出的属性注册信息
    private final Map<String, Long> propertyRegistrations = new HashMap<>();
    
    /**
     * 处理 napi_define_properties 调用
     */
    public void processDefineProperties(Function callee, AbsEnv absEnv, Function caller) {
        Logging.info("Resolving dynamic registered napi from napi_define_properties");
        
        // 解析属性描述符数组的长度（第3个参数）
        KSet sizeKSet = CheckerBase.getParamKSet(callee, 2, absEnv);
        long size = extractGlobalValue(sizeKSet, absEnv, "property count in napi_define_properties");
        Logging.info("size of descriptors is: " + size);
        
        // 解析属性描述符数组指针（第4个参数）
        KSet descriptorArrayKSet = CheckerBase.getParamKSet(callee, 3, absEnv);
        
        // 先尝试直接解析descriptor数组（更快的方法）
        boolean resolvedDirectly = resolveFromDescriptorArray(descriptorArrayKSet, (int) size, absEnv);
        
        // 只有在直接解析失败且数组大小较大时才尝试memcpy方式
        if (!resolvedDirectly && size > 3) { // 只有大于3个属性时才考虑memcpy优化
            Logging.info("Direct approach failed for large array, trying memcpy resolution");
            resolveFromMemcpy(caller, (int) size);
        } else if (!resolvedDirectly) {
            Logging.info("Direct approach failed but array is small, skipping memcpy resolution");
        }
    }
    
    /**
     * 从memcpy参数中解析动态注册
     * 优化版本：只在当前函数内查找memcpy调用，而不是全局搜索
     */
    private boolean resolveFromMemcpy(Function function, int size) {
        Logging.info("Trying to resolve from memcpy calls within function: " + function.getName());
        
        // 只在当前函数内查找memcpy调用
        boolean found = false;
        Address functionStart = function.getEntryPoint();
        Address functionEnd = function.getBody().getMaxAddress();
        
        // 遍历当前函数的所有指令，查找对memcpy的调用
        Address currentAddr = functionStart;
        while (currentAddr != null && currentAddr.compareTo(functionEnd) <= 0) {
            // 检查当前地址是否有对memcpy的引用
            Reference[] referencesFrom = GlobalState.currentProgram.getReferenceManager().getReferencesFrom(currentAddr);
            
            for (Reference ref : referencesFrom) {
                if (ref.getReferenceType().isCall()) {
                    Function calledFunction = GlobalState.flatAPI.getFunctionAt(ref.getToAddress());
                    if (calledFunction != null && "memcpy".equals(calledFunction.getName())) {
                        Logging.info("Found memcpy call at: " + currentAddr);
                        
                        // 尝试解析这个memcpy调用的参数
                        if (resolveMemcpyCall(currentAddr, function, size)) {
                            found = true;
                        }
                    }
                }
            }
            
            // 移动到下一条指令
            currentAddr = GlobalState.flatAPI.getInstructionAfter(GlobalState.flatAPI.getInstructionAt(currentAddr)).getAddress();
        }
        
        if (!found) {
            Logging.info("No memcpy calls found in function " + function.getName());
        }
        
        return found;
    }
    
    /**
     * 解析特定的memcpy调用
     */
    private boolean resolveMemcpyCall(Address callSite, Function caller, int expectedSize) {
        try {
            // 获取调用点的上下文
            Context context = null;
            for (Context ctx : Context.getContext(caller)) {
                if (ctx.getAbsEnvIn().containsKey(callSite)) {
                    context = ctx;
                    break;
                }
            }
            
            if (context == null) {
                Logging.warn("No context found for memcpy call at " + callSite);
                return false;
            }
            
            AbsEnv absEnv = context.getAbsEnvIn().get(callSite);
            if (absEnv == null) {
                Logging.warn("No absEnv found for memcpy call at " + callSite);
                return false;
            }
            
            // 获取memcpy的源地址参数（第2个参数）
            Function memcpyFunc = GlobalState.flatAPI.getFunctionAt(
                GlobalState.currentProgram.getReferenceManager().getReferencesFrom(callSite)[0].getToAddress()
            );
            
            KSet srcPtrKSet = CheckerBase.getParamKSet(memcpyFunc, 1, absEnv);
            
            if (!srcPtrKSet.isNormal() || srcPtrKSet.isBot()) {
                Logging.warn("Cannot resolve memcpy source parameter at " + callSite);
                return false;
            }
            
            // 解析源地址指向的数据
            for (AbsVal srcPtr : srcPtrKSet) {
                if (srcPtr.getRegion().isGlobal()) {
                    long srcAddr = srcPtr.getValue();
                    Logging.info("Resolving memcpy source at: 0x" + Long.toHexString(srcAddr));
                    int resolved = resolveDescriptorsAt(srcAddr, expectedSize);
                    return resolved > 0;
                }
            }
            
            Logging.warn("memcpy source is not global at " + callSite);
            return false;
            
        } catch (Exception e) {
            Logging.error("Error resolving memcpy call at " + callSite + ": " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 直接从descriptor数组解析
     * @return 是否成功解析出至少一个属性
     */
    private boolean resolveFromDescriptorArray(KSet descriptorArrayKSet, int size, AbsEnv absEnv) {
        Logging.info("Resolving descriptors from direct array access");
        
        int resolvedCount = 0;
        
        for (AbsVal arrayPtr : descriptorArrayKSet) {
            if (!arrayPtr.getRegion().isGlobal()) {
                if (arrayPtr.getRegion().isLocal()) {
                    Logging.info("Found local descriptor array, trying to resolve...");
                    resolvedCount += resolveLocalDescriptorArray(arrayPtr, size, absEnv);
                } else {
                    Logging.warn("Descriptor array is neither global nor local: " + arrayPtr.getRegion().getClass().getSimpleName());
                }
                continue;
            }
            
            // 全局descriptor数组的情况
            long arrayAddr = arrayPtr.getValue();
            Logging.info("Found global descriptor array at: 0x" + Long.toHexString(arrayAddr));
            resolvedCount += resolveDescriptorsAt(arrayAddr, size);
        }
        
        boolean success = resolvedCount > 0;
        Logging.info("Direct array resolution " + (success ? "succeeded" : "failed") + 
                    ", resolved " + resolvedCount + " properties");
        return success;
    }
    
    /**
     * 解析栈上构造的descriptor数组
     * @return 成功解析的属性数量
     */
    private int resolveLocalDescriptorArray(AbsVal arrayPtr, int size, AbsEnv absEnv) {
        RegionBase region = arrayPtr.getRegion();
        long baseOffset = arrayPtr.getValue();
        int ptrSize = MyGlobalState.defaultPointerSize;
        int structSize = ptrSize * 8; // napi_property_descriptor结构体大小
        
        Logging.info("Resolving local descriptor array, base offset: " + baseOffset + ", size: " + size);
        
        int resolvedCount = 0;
        for (int i = 0; i < size; i++) {
            long structOffset = baseOffset + i * structSize;
            
            // 解析每个descriptor结构体的字段
            String utf8name = resolveLocalDescriptorField(region, structOffset + ptrSize * 0, absEnv);
            Long methodPtr = resolveLocalDescriptorMethodPtr(region, structOffset + ptrSize * 2, absEnv);
            
            if (utf8name != null && methodPtr != null) {
                Logging.info("Found local descriptor: " + utf8name + " at 0x" + Long.toHexString(methodPtr));
                addPropertyRegistration(utf8name, methodPtr);
                resolvedCount++;
            } else {
                Logging.warn("Failed to resolve local descriptor at offset: " + structOffset);
            }
        }
        return resolvedCount;
    }
    
    /**
     * 直接解析全局descriptor数组
     * @return 成功解析的属性数量
     */
    private int resolveDescriptorsAt(long ptr, int size) {
        int ptrSize = MyGlobalState.defaultPointerSize;
        int structSize = ptrSize * 8;
        
        int resolvedCount = 0;
        for (int index = 0; index < size; index++) {
            try {
                Address base = GlobalState.flatAPI.toAddr(ptr + index * structSize);
                Address utf8nameAddr = base.add(ptrSize * 0);
                Address methodAddr = base.add(ptrSize * 2);

                // 解析函数名
                Address utf8nameTrueAddr = GlobalState.flatAPI.toAddr(
                    ModuleInitChecker.getValueFromAddrWithPtrSize(utf8nameAddr.getOffset(), ptrSize));
                String utf8nameStr = ModuleInitChecker.getStrFromAddr(utf8nameTrueAddr.getOffset());

                // 解析方法指针
                Address methodTrueAddr = GlobalState.flatAPI.toAddr(
                    ModuleInitChecker.getValueFromAddrWithPtrSize(methodAddr.getOffset(), ptrSize));

                if (utf8nameStr != null && methodTrueAddr != null) {
                    Logging.info("Find dynamic registered napi: " + utf8nameStr + " at 0x" + Long.toHexString(methodTrueAddr.getOffset()));
                    addPropertyRegistration(utf8nameStr, methodTrueAddr.getOffset());
                    resolvedCount++;
                } else {
                    Logging.warn("Failed to resolve NAPI descriptor at 0x" + Long.toHexString(base.getOffset()));
                }
            } catch (Exception e) {
                Logging.error("Error resolving descriptor at index " + index + ": " + e.getMessage());
            }
        }
        return resolvedCount;
    }
    
    // 工具方法 - 使用ModuleInitChecker的增强解析功能
    private long extractGlobalValue(KSet kSet, AbsEnv absEnv, String context) {
        Long result = ModuleInitChecker.resolveLongFromKSet(kSet, absEnv, context);
        return (result != null) ? result : 0;
    }
    
    private String resolveLocalDescriptorField(RegionBase region, long fieldOffset, AbsEnv absEnv) {
        ALoc fieldLoc = ALoc.getALoc(region, fieldOffset, MyGlobalState.defaultPointerSize);
        KSet fieldKSet = absEnv.get(fieldLoc);
        
        // 使用增强的字符串解析功能
        return ModuleInitChecker.resolveStringFromKSet(fieldKSet, absEnv, "local property descriptor field");
    }
    
    private Long resolveLocalDescriptorMethodPtr(RegionBase region, long fieldOffset, AbsEnv absEnv) {
        ALoc fieldLoc = ALoc.getALoc(region, fieldOffset, MyGlobalState.defaultPointerSize);
        KSet fieldKSet = absEnv.get(fieldLoc);
        
        // 使用增强的值解析功能
        return ModuleInitChecker.resolveLongFromKSet(fieldKSet, absEnv, "local property descriptor method ptr");
    }
    
    /**
     * 获取所有解析出的属性注册
     */
    public Map<String, Long> getAllPropertyRegistrations() {
        return propertyRegistrations;
    }
    
    /**
     * 添加属性注册
     */
    private void addPropertyRegistration(String propertyName, Long functionPtr) {
        if (propertyName != null && functionPtr != null && functionPtr != 0) {
            propertyRegistrations.put(propertyName, functionPtr);
            Logging.info("Added property registration: " + propertyName + " -> 0x" + Long.toHexString(functionPtr));
        }
    }
}
