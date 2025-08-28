package hust.cse.ohnapisummary.checkers;

import com.bai.env.*;
import com.bai.env.region.RegionBase;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import com.bai.checkers.CheckerBase;
import java.util.HashMap;
import java.util.Map;

/**
 * 函数注册解析器 - 处理 napi_create_function + napi_set_named_property 调用
 */
class FunctionRegistrationResolver {
    
    private final Map<String, FunctionRegistration> functionRegistrations = new HashMap<>();
    
    /**
     * 函数注册信息
     */
    static class FunctionRegistration {
        String functionName;
        Long functionPtr;
        
        FunctionRegistration(String functionName, Long functionPtr) {
            this.functionName = functionName;
            this.functionPtr = functionPtr;
        }
    }
    
    /**
     * 处理 napi_create_function 调用
     * 记录下函数名和函数指针，等待 napi_set_named_property 调用
     */
    public void processCreateFunction(Function callee, AbsEnv absEnv, Context context) {
        Logging.info("Resolving function creation from napi_create_function");
        
        // 解析函数名（第2个参数）
        KSet functionNameKSet = CheckerBase.getParamKSet(callee, 1, absEnv);
        String functionName = extractGlobalString(functionNameKSet, absEnv, "function name in napi_create_function");
        
        // 解析函数指针（第4个参数）
        KSet functionPtrKSet = CheckerBase.getParamKSet(callee, 3, absEnv);
        Long functionPtr = extractGlobalValue(functionPtrKSet, absEnv, "function ptr in napi_create_function");
        
        if (functionName != null && functionPtr != null) {
            Logging.info("Found function creation: " + functionName + " at 0x" + Long.toHexString(functionPtr));
            functionRegistrations.put(functionName, new FunctionRegistration(functionName, functionPtr));
        } else {
            Logging.warn("Failed to resolve function creation - functionName: " + functionName + ", functionPtr: " + functionPtr);
        }
    }
    
    /**
     * 处理 napi_set_named_property 调用
     * 这通常是将前面创建的函数设置到导出对象上
     */
    public void processSetNamedProperty(Function callee, AbsEnv absEnv, Context context) {
        Logging.info("Resolving property setting from napi_set_named_property");
        
        // 解析属性名（第2个参数）
        KSet propertyNameKSet = CheckerBase.getParamKSet(callee, 1, absEnv);
        String propertyName = extractGlobalString(propertyNameKSet, absEnv, "property name in napi_set_named_property");
        
        // 获取要设置的值（第3个参数），这可能是之前创建的函数
        KSet valueKSet = CheckerBase.getParamKSet(callee, 2, absEnv);
        
        if (propertyName != null) {
            Logging.info("Found property setting: " + propertyName);
            
            // 检查是否有匹配的函数创建记录
            if (functionRegistrations.containsKey(propertyName)) {
                FunctionRegistration funcReg = functionRegistrations.get(propertyName);
                Logging.info("Confirmed function registration: " + propertyName + " -> 0x" + Long.toHexString(funcReg.functionPtr));
            } else {
                // 可能是其他类型的属性设置，记录下来
                Logging.info("Property setting without preceding function creation: " + propertyName);
            }
        } else {
            Logging.warn("Failed to resolve property name in napi_set_named_property");
        }
    }
    
    /**
     * 处理直接的函数注册（函数名和函数指针直接传递）
     */
    public void processDirectFunctionRegistration(String functionName, Long functionPtr) {
        if (functionName != null && functionPtr != null) {
            Logging.info("Direct function registration: " + functionName + " at 0x" + Long.toHexString(functionPtr));
            functionRegistrations.put(functionName, new FunctionRegistration(functionName, functionPtr));
        }
    }
    
    /**
     * 处理通过数组批量注册的情况
     * 例如：通过包含函数名和函数指针的结构体数组进行批量注册
     */
    public void processBatchFunctionRegistration(KSet arrayKSet, int functionCount, AbsEnv absEnv) {
        for (AbsVal arrayPtr : arrayKSet) {
            if (!arrayPtr.getRegion().isGlobal()) {
                if (arrayPtr.getRegion().isLocal()) {
                    Logging.info("Found local function array, trying to resolve...");
                    resolveLocalFunctionArray(arrayPtr, functionCount, absEnv);
                } else {
                    Logging.warn("Function array is neither global nor local: " + arrayPtr.getRegion().getClass().getSimpleName());
                }
                continue;
            }
            
            // 全局函数数组的情况
            long arrayAddr = arrayPtr.getValue();
            Logging.info("Found global function array at: 0x" + Long.toHexString(arrayAddr));
            resolveGlobalFunctionArray(arrayAddr, functionCount);
        }
    }
    
    /**
     * 解析全局函数数组
     */
    private void resolveGlobalFunctionArray(long ptr, int functionCount) {
        int ptrSize = hust.cse.ohnapisummary.util.MyGlobalState.defaultPointerSize;
        int structSize = ptrSize * 2; // 假设每个元素包含函数名指针和函数指针
        
        for (int i = 0; i < functionCount; i++) {
            Address base = GlobalState.flatAPI.toAddr(ptr + i * structSize);
            
            try {
                // 解析函数名
                Address nameAddr = base;
                long namePtrValue = ModuleInitChecker.getValueFromAddrWithPtrSize(nameAddr.getOffset(), ptrSize);
                String functionName = ModuleInitChecker.getStrFromAddr(namePtrValue);
                
                // 解析函数指针
                Address funcAddr = base.add(ptrSize);
                long funcPtrValue = ModuleInitChecker.getValueFromAddrWithPtrSize(funcAddr.getOffset(), ptrSize);
                
                if (functionName != null && funcPtrValue != 0) {
                    functionRegistrations.put(functionName, new FunctionRegistration(functionName, funcPtrValue));
                    Logging.info("Found batch function registration: " + functionName + " at 0x" + Long.toHexString(funcPtrValue));
                }
            } catch (Exception e) {
                Logging.error("Failed to read function registration at index " + i + ": " + e.getMessage());
            }
        }
    }
    
    /**
     * 解析栈上的函数数组
     */
    private void resolveLocalFunctionArray(AbsVal arrayPtr, int functionCount, AbsEnv absEnv) {
        RegionBase region = arrayPtr.getRegion();
        long baseOffset = arrayPtr.getValue();
        int ptrSize = hust.cse.ohnapisummary.util.MyGlobalState.defaultPointerSize;
        int structSize = ptrSize * 2; // 假设每个元素包含函数名指针和函数指针
        
        Logging.info("Resolving local function array, base offset: " + baseOffset + ", count: " + functionCount);
        
        for (int i = 0; i < functionCount; i++) {
            long structOffset = baseOffset + i * structSize;
            
            // 解析函数名
            String functionName = resolveLocalFunctionField(region, structOffset, absEnv);
            
            // 解析函数指针
            Long functionPtr = resolveLocalFunctionPtr(region, structOffset + ptrSize, absEnv);
            
            if (functionName != null && functionPtr != null && functionPtr != 0) {
                functionRegistrations.put(functionName, new FunctionRegistration(functionName, functionPtr));
                Logging.info("Found local batch function registration: " + functionName + " at 0x" + Long.toHexString(functionPtr));
            } else {
                Logging.warn("Failed to resolve local function registration at offset: " + structOffset);
            }
        }
    }
    
    /**
     * 获取所有函数注册信息
     */
    public Map<String, FunctionRegistration> getAllFunctionRegistrations() {
        return functionRegistrations;
    }
    
    /**
     * 检查是否已有指定名称的函数注册
     */
    public boolean hasFunctionRegistration(String functionName) {
        return functionRegistrations.containsKey(functionName);
    }
    
    /**
     * 获取指定函数的注册信息
     */
    public FunctionRegistration getFunctionRegistration(String functionName) {
        return functionRegistrations.get(functionName);
    }
    
    // 工具方法 - 使用ModuleInitChecker的增强解析功能
    private String extractGlobalString(KSet kSet, AbsEnv absEnv, String context) {
        return ModuleInitChecker.resolveStringFromKSet(kSet, absEnv, context);
    }
    
    private Long extractGlobalValue(KSet kSet, AbsEnv absEnv, String context) {
        return ModuleInitChecker.resolveLongFromKSet(kSet, absEnv, context);
    }
    
    private String resolveLocalFunctionField(RegionBase region, long fieldOffset, AbsEnv absEnv) {
        ALoc fieldLoc = ALoc.getALoc(region, fieldOffset, hust.cse.ohnapisummary.util.MyGlobalState.defaultPointerSize);
        KSet fieldKSet = absEnv.get(fieldLoc);
        
        // 使用增强的字符串解析功能
        return ModuleInitChecker.resolveStringFromKSet(fieldKSet, absEnv, "local function field");
    }
    
    private Long resolveLocalFunctionPtr(RegionBase region, long fieldOffset, AbsEnv absEnv) {
        ALoc fieldLoc = ALoc.getALoc(region, fieldOffset, hust.cse.ohnapisummary.util.MyGlobalState.defaultPointerSize);
        KSet fieldKSet = absEnv.get(fieldLoc);
        
        // 使用增强的值解析功能
        return ModuleInitChecker.resolveLongFromKSet(fieldKSet, absEnv, "local function ptr");
    }
}
