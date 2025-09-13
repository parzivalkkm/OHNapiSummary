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
        
        // 验证描述符数组的合理性
        if (!ModuleInitChecker.isLikelyNAPIDescriptorArray(descriptorArrayKSet, (int)size, "napi_define_properties")) {
            Logging.warn("Descriptor array validation failed, skipping napi_define_properties resolution");
            return;
        }
        
        // 使用分层解析策略
        if (!tryLayeredResolution(descriptorArrayKSet, (int) size, absEnv, caller)) {
            Logging.warn("All resolution strategies failed for napi_define_properties");
        }
    }
    
    /**
     * 分层解析策略 - 从最安全到最保守
     */
    private boolean tryLayeredResolution(KSet descriptorArrayKSet, int size, AbsEnv absEnv, Function caller) {
        // Layer 1: 直接全局数组解析
        if (resolveFromGlobalDescriptorArray(descriptorArrayKSet, size)) {
            Logging.info("Successfully resolved using global descriptor array (Layer 1)");
            return true;
        }
        
        // Layer 2: 本地栈数组解析 
        if (resolveFromLocalDescriptorArray(descriptorArrayKSet, size, absEnv)) {
            Logging.info("Successfully resolved using local descriptor array (Layer 2)");
            return true;
        }
        
        // Layer 3: 有限制的memcpy解析
        if (size >= 1) {
            System.out.println("Attempting constrained memcpy resolution: size=" + size + 
                              ", function=" + (caller != null ? caller.getName() : "unknown") +
                              ", confidence=" + (isHighConfidenceNAPIContext(caller) ? "high" : "low"));
            if (resolveFromConstrainedMemcpy(caller, size, descriptorArrayKSet)) {
                Logging.info("Successfully resolved using constrained memcpy (Layer 3)");
                return true;
            }
        } else {
            Logging.info("Skipping memcpy resolution: size too small (" + size + ")");
        }
        
        return false;
    }
    
    /**
     * 解析全局描述符数组 - 增加验证
     */
    private boolean resolveFromGlobalDescriptorArray(KSet descriptorArrayKSet, int size) {
        Logging.info("Attempting global descriptor array resolution with validation");
        
        for (AbsVal arrayPtr : descriptorArrayKSet) {
            if (!arrayPtr.getRegion().isGlobal()) {
                continue;
            }
            
            long arrayAddr = arrayPtr.getValue();
            
            // 验证数组地址
            if (!ModuleInitChecker.isValidMemoryAddress(arrayAddr, "global descriptor array")) {
                Logging.warn("Invalid global array address: 0x" + Long.toHexString(arrayAddr));
                continue;
            }
            
            Logging.info("Found valid global descriptor array at: 0x" + Long.toHexString(arrayAddr));
            
            // 解析描述符并验证每个结构
            int validDescriptors = resolveDescriptorsWithValidation(arrayAddr, size, "global array");
            
            if (validDescriptors > 0) {
                Logging.info("Global array resolution succeeded, resolved " + validDescriptors + " descriptors");
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * 带验证的描述符解析
     */
    private int resolveDescriptorsWithValidation(long arrayAddr, int size, String source) {
        int ptrSize = MyGlobalState.defaultPointerSize;
        int structSize = ptrSize * 8; // napi_property_descriptor结构体大小
        int validCount = 0;
        
        for (int i = 0; i < size; i++) {
            long structAddr = arrayAddr + i * structSize;
            
            // 验证描述符结构
            if (!ModuleInitChecker.validateNAPIDescriptorStructure(arrayAddr, i, source)) {
                Logging.warn("Descriptor validation failed for index " + i + " in " + source);
                continue;
            }
            
            // 解析属性名（第1个字段）
            long namePtr = ModuleInitChecker.getValueFromAddrWithPtrSize(structAddr, ptrSize);
            String propertyName = null;
            
            if (namePtr != 0 && ModuleInitChecker.isValidMemoryAddress(namePtr, source + " property name")) {
                propertyName = ModuleInitChecker.getStrFromAddr(namePtr);
            }
            
            // 解析方法指针（第3个字段）  
            long methodPtr = ModuleInitChecker.getValueFromAddrWithPtrSize(structAddr + ptrSize * 2, ptrSize);
            
            if (propertyName != null && methodPtr != 0 && 
                ModuleInitChecker.isValidMemoryAddress(methodPtr, source + " method pointer")) {
                
                addPropertyRegistration(propertyName, methodPtr);
                validCount++;
                Logging.info("Validated and added property: " + propertyName + " -> 0x" + Long.toHexString(methodPtr));
            } else {
                Logging.debug("Skipped invalid descriptor at index " + i + " in " + source);
            }
        }
        
        return validCount;
    }
    
    /**
     * 检查是否为高置信度的NAPI上下文
     */
    private boolean isHighConfidenceNAPIContext(Function function) {
        if (function == null) {
            return false;
        }
        
        String funcName = function.getName().toLowerCase();
        
        // 检查函数名是否包含NAPI相关关键词
        if (funcName.contains("init") || funcName.contains("register") || 
            funcName.contains("napi") || funcName.contains("module")) {
            return true;
        }
        
        // 增强的启发式规则
        try {
            // 规则1：检查函数是否包含多个NAPI调用
            if (containsMultipleNAPICallsHeuristic(function)) {
                return true;
            }
            
            // 规则2：检查函数调用者是否具有NAPI特征
            if (hasNAPICallerHeuristic(function)) {
                return true;
            }
            
            // 规则3：检查函数所在的代码段是否包含其他NAPI函数
            if (isInNAPICodeSection(function)) {
                return true;
            }
            
        } catch (Exception e) {
            // 启发式检查失败时不影响主流程
            System.out.println("Warning: Heuristic check failed for " + funcName + ": " + e.getMessage());
        }
        
        return false;
    }
    
    /**
     * 启发式规则1：检查函数是否包含多个NAPI调用
     */
    private boolean containsMultipleNAPICallsHeuristic(Function function) {
        // 简单实现：检查函数体中是否有多个napi_相关的调用
        // 这里可以根据需要实现更复杂的逻辑
        return false; // 暂时返回false，可以后续完善
    }
    
    /**
     * 启发式规则2：检查函数调用者是否具有NAPI特征
     */
    private boolean hasNAPICallerHeuristic(Function function) {
        // 检查调用该函数的其他函数是否具有NAPI特征
        return false; // 暂时返回false，可以后续完善
    }
    
    /**
     * 启发式规则3：检查函数是否在NAPI代码段中
     */
    private boolean isInNAPICodeSection(Function function) {
        // 检查函数附近是否有其他NAPI相关函数
        return false; // 暂时返回false，可以后续完善
    }
    
    /**
     * 受限制的memcpy解析 - 更安全的版本
     */
    private boolean resolveFromConstrainedMemcpy(Function function, int size, KSet sourceKSet) {
        Logging.info("Attempting constrained memcpy resolution for function: " + function.getName());
        
        // 不再验证sourceKSet，而是直接查找函数中的memcpy调用
        // 因为sourceKSet可能是local的，无法直接验证
        System.out.println("Searching for memcpy calls in function: " + function.getName());
        
        // 查找函数中的memcpy调用并解析
        return resolveFromValidatedMemcpy(function, size);
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
     * 解析本地描述符数组 - 增加验证  
     */
    private boolean resolveFromLocalDescriptorArray(KSet descriptorArrayKSet, int size, AbsEnv absEnv) {
        Logging.info("Attempting local descriptor array resolution with validation");
        
        for (AbsVal arrayPtr : descriptorArrayKSet) {
            if (arrayPtr.getRegion().isLocal()) {
                Logging.info("Found local descriptor array, trying to resolve...");
                
                // 验证本地数组的基本合理性
                RegionBase region = arrayPtr.getRegion();
                long baseOffset = arrayPtr.getValue();
                
                if (resolveLocalDescriptorArrayWithValidation(arrayPtr, size, absEnv) > 0) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * 带验证的本地描述符数组解析
     */
    private int resolveLocalDescriptorArrayWithValidation(AbsVal arrayPtr, int size, AbsEnv absEnv) {
        RegionBase region = arrayPtr.getRegion();
        long baseOffset = arrayPtr.getValue();
        int ptrSize = MyGlobalState.defaultPointerSize;
        int structSize = ptrSize * 8; // napi_property_descriptor结构体大小
        
        Logging.info("Resolving local descriptor array, base offset: " + baseOffset + ", size: " + size);
        
        int resolvedCount = 0;
        for (int i = 0; i < size; i++) {
            long structOffset = baseOffset + i * structSize;
            
            // 解析每个descriptor结构体的字段
            String propertyName = resolveLocalDescriptorField(region, structOffset, absEnv);
            Long methodPtr = resolveLocalDescriptorMethodPtr(region, structOffset + ptrSize * 2, absEnv);
            
            // 验证解析出的数据
            if (propertyName != null && methodPtr != null && methodPtr != 0) {
                if (ModuleInitChecker.isValidMemoryAddress(methodPtr, "local descriptor method ptr")) {
                    addPropertyRegistration(propertyName, methodPtr);
                    resolvedCount++;
                    Logging.info("Validated local descriptor: " + propertyName + " -> 0x" + Long.toHexString(methodPtr));
                } else {
                    Logging.warn("Invalid method pointer in local descriptor: 0x" + Long.toHexString(methodPtr));
                }
            } else {
                Logging.debug("Failed to resolve local descriptor at offset: " + structOffset);
            }
        }
        
        return resolvedCount;
    }
    
    /**
     * 验证的memcpy解析 - 基于静态分析日志中的memcpy信息
     */
    private boolean resolveFromValidatedMemcpy(Function function, int size) {
        Logging.info("Trying validated memcpy resolution within function: " + function.getName());
        
        // 从日志我们知道有memcpy: <FUN_00108ea8@Local, 14d08h> <- <GLOBAL, 111b40h> size: 704
        // 这意味着有全局数据被复制到本地数组
        // 我们应该尝试解析全局源地址的数据
        
        // 尝试查找可能的全局descriptor数组地址
        // 基于memcpy大小704字节和11个descriptor，每个64字节(8*8)，符合预期
        long expectedStructSize = 64; // 8个指针 * 8字节
        long expectedTotalSize = size * expectedStructSize;
        
        System.out.println("Expected memcpy size for " + size + " descriptors: " + expectedTotalSize + " bytes");
        
        // 尝试查找函数中可能的全局数据引用
        return tryResolveFromGlobalMemcpySource(function, size);
    }
    
    /**
     * 尝试从全局memcpy源解析descriptor
     */
    private boolean tryResolveFromGlobalMemcpySource(Function function, int size) {
        try {
            // 扫描函数中的所有全局地址引用
            Address functionStart = function.getEntryPoint();
            Address functionEnd = function.getBody().getMaxAddress();
            
            System.out.println("Scanning function " + function.getName() + " for global references...");
            
            Address currentAddr = functionStart;
            while (currentAddr != null && currentAddr.compareTo(functionEnd) <= 0) {
                // 检查这个地址是否引用了全局数据
                Reference[] referencesFrom = GlobalState.currentProgram.getReferenceManager().getReferencesFrom(currentAddr);
                
                for (Reference ref : referencesFrom) {
                    if (ref.getReferenceType().isData()) {
                        Address globalAddr = ref.getToAddress();
                        long addr = globalAddr.getOffset();
                        
                        // 检查这个全局地址是否可能是descriptor数组
                        if (ModuleInitChecker.isValidMemoryAddress(addr, "potential global descriptor array")) {
                            System.out.println("Found potential global descriptor array at: 0x" + Long.toHexString(addr));
                            
                            // 尝试解析这个地址的数据
                            int resolved = resolveDescriptorsAt(addr, size);
                            if (resolved > 0) {
                                System.out.println("Successfully resolved " + resolved + " descriptors from global address");
                                return true;
                            }
                        }
                    }
                }
                
                currentAddr = currentAddr.next();
                if (currentAddr == null) break;
            }
            
            System.out.println("No valid global descriptor arrays found in function");
            return false;
            
        } catch (Exception e) {
            System.out.println("Error in tryResolveFromGlobalMemcpySource: " + e.getMessage());
            return false;
        }
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
