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
 * 类注册解析器 - 处理 napi_define_class 调用
 */
class ClassRegistrationResolver {
    
    private final Map<String, ClassDefinition> classDefinitions = new HashMap<>();
    
    /**
     * 类定义信息
     */
    static class ClassDefinition {
        String className;
        Long constructorPtr;
        Map<String, PropertyDescriptor> properties = new HashMap<>();
        
        ClassDefinition(String className, Long constructorPtr) {
            this.className = className;
            this.constructorPtr = constructorPtr;
        }
    }
    
    /**
     * 属性描述符
     */
    static class PropertyDescriptor {
        String propertyName;
        Long methodPtr;     // 方法指针
        Long getterPtr;     // getter指针
        Long setterPtr;     // setter指针
        
        PropertyDescriptor(String propertyName) {
            this.propertyName = propertyName;
        }
    }
    
    /**
     * 处理 napi_define_class 调用
     */
    public void processDefineClass(Function callee, AbsEnv absEnv, Context context) {
        Logging.info("Resolving class definition from napi_define_class");
        
        try {
            // 添加详细的诊断信息
            Logging.debug("=== Class Definition Analysis ===");
            Logging.debug("Function: " + callee.getName() + " at " + callee.getEntryPoint());
            Logging.debug("AbsEnv available: " + (absEnv != null));
            Logging.debug("Parameter count: " + callee.getParameterCount());
            
            // 逐个检查参数KSet状态
            for (int i = 0; i < Math.min(callee.getParameterCount(), 7); i++) {
                try {
                    KSet paramKSet = CheckerBase.getParamKSet(callee, i, absEnv);
                    if (paramKSet == null) {
                        Logging.warn("Parameter " + i + " KSet is null");
                    } else {
                        Logging.debug("Parameter " + i + " KSet: " + paramKSet.getClass().getSimpleName() + 
                                    " (normal=" + paramKSet.isNormal() + ", bot=" + paramKSet.isBot() + ")");
                        
                        // 检查KSet内部状态以诊断null问题
                        try {
                            String ksetStr = paramKSet.toString();
                            if (ksetStr.contains("kSet=null") || ksetStr.contains("null")) {
                                Logging.warn("Parameter " + i + " contains null reference: " + ksetStr);
                            }
                            
                            // 尝试迭代以触发潜在的null pointer异常
                            int elementCount = 0;
                            for (Object elem : paramKSet) {
                                elementCount++;
                                if (elementCount > 3) break; // 限制迭代次数
                            }
                            Logging.debug("Parameter " + i + " successfully iterated " + elementCount + " elements");
                            
                        } catch (Exception iterEx) {
                            Logging.error("Parameter " + i + " iteration failed: " + iterEx.getMessage());
                            if (iterEx.getMessage().contains("kSet is null")) {
                                Logging.error("CONFIRMED: Parameter " + i + " has internal kSet null issue");
                            }
                        }
                    }
                } catch (Exception paramEx) {
                    Logging.error("Failed to analyze parameter " + i + ": " + paramEx.getMessage());
                }
            }
            
            // 解析类名（第2个参数） - 使用带诊断的方法
            KSet classNameKSet = CheckerBase.getParamKSet(callee, 1, absEnv);
            String className = extractStringWithDiagnostics(classNameKSet, absEnv, "class name in napi_define_class", 1);
            
            // 解析构造函数指针（第4个参数）
            KSet constructorKSet = CheckerBase.getParamKSet(callee, 3, absEnv);
            Long constructorPtr = extractValueWithDiagnostics(constructorKSet, absEnv, "constructor ptr in napi_define_class", 3);
            
            // 解析属性数量（第6个参数）
            KSet propertyCountKSet = CheckerBase.getParamKSet(callee, 5, absEnv);
            Long propertyCountLong = extractValueWithDiagnostics(propertyCountKSet, absEnv, "property count in napi_define_class", 5);
            long propertyCount = (propertyCountLong != null) ? propertyCountLong : 0;
            
            // 解析属性描述符数组（第7个参数）
            KSet propertiesKSet = CheckerBase.getParamKSet(callee, 6, absEnv);
            
            // 记录解析结果
            Logging.info("=== Extraction Results ===");
            Logging.info("Class name: " + (className != null ? className : "FAILED"));
            Logging.info("Constructor pointer: " + (constructorPtr != null ? "0x" + Long.toHexString(constructorPtr) : "FAILED"));
            Logging.info("Property count: " + propertyCount);
            
            // 如果基本信息解析失败，使用备用策略
            if (className == null) {
                className = "UnknownClass_" + callee.getEntryPoint().toString().hashCode();
                Logging.warn("Using fallback class name: " + className);
            }
            
            // 验证构造函数指针 - 使用更宽松的检查
            boolean validConstructor = false;
            if (constructorPtr != null) {
                validConstructor = ModuleInitChecker.isValidConstructorPointer(constructorPtr, className);
                if (!validConstructor) {
                    Logging.warn("Constructor pointer validation failed for class: " + className + 
                               " (ptr: 0x" + Long.toHexString(constructorPtr) + ")");
                    // 使用放宽的验证
                    validConstructor = (constructorPtr > 0x1000 && constructorPtr < 0x8000000000000000L);
                    if (validConstructor) {
                        Logging.info("Relaxed validation passed for constructor pointer");
                    }
                }
            }
            
            if (className != null && constructorPtr != null && validConstructor) {
                Logging.info("Successfully resolved class definition: " + className + 
                           " with constructor at 0x" + Long.toHexString(constructorPtr));
                ClassDefinition classDef = new ClassDefinition(className, constructorPtr);
                
                // 解析属性描述符 - 增加验证
                if (propertyCount > 0 && propertiesKSet != null) {
                    Logging.debug("Attempting to resolve " + propertyCount + " class properties");
                    try {
                        if (ModuleInitChecker.isLikelyNAPIDescriptorArray(propertiesKSet, (int)propertyCount, "class properties")) {
                            resolveClassProperties(propertiesKSet, (int) propertyCount, absEnv, classDef);
                            Logging.info("Successfully resolved class properties for " + className);
                        } else {
                            Logging.warn("Class properties array validation failed for class: " + className);
                        }
                    } catch (Exception propEx) {
                        Logging.error("Error resolving class properties: " + propEx.getMessage());
                    }
                }
                
                classDefinitions.put(className, classDef);
                Logging.info("Class definition stored: " + className);
                
            } else {
                Logging.warn("Failed to resolve complete class definition");
                Logging.warn("  - className: " + className);
                Logging.warn("  - constructorPtr: " + (constructorPtr != null ? "0x" + Long.toHexString(constructorPtr) : "null"));
                Logging.warn("  - validConstructor: " + validConstructor);
                
                // 即使失败，也记录部分信息用于分析
                if (className != null) {
                    ClassDefinition partialDef = new ClassDefinition(className, constructorPtr != null ? constructorPtr : 0L);
                    classDefinitions.put(className + "_PARTIAL", partialDef);
                    Logging.info("Stored partial class definition for analysis");
                }
            }
            
        } catch (Exception e) {
            Logging.error("Exception in processDefineClass: " + e.getMessage());
            e.printStackTrace();
            
            // 记录异常发生时的上下文
            try {
                Logging.error("Context - Function: " + callee.getName());
                Logging.error("Context - Entry point: " + callee.getEntryPoint());
                Logging.error("Context - Parameter count: " + callee.getParameterCount());
            } catch (Exception contextEx) {
                Logging.error("Failed to log error context: " + contextEx.getMessage());
            }
        }
    }
    
    /**
     * 解析类的属性描述符数组
     */
    private void resolveClassProperties(KSet propertiesKSet, int propertyCount, AbsEnv absEnv, ClassDefinition classDef) {
        if (propertiesKSet == null || propertiesKSet.isBot()) {
            Logging.warn("Properties KSet is null or bot, skipping class property resolution");
            return;
        }
        
        try {
            for (AbsVal arrayPtr : propertiesKSet) {
                if (!arrayPtr.getRegion().isGlobal()) {
                    if (arrayPtr.getRegion().isLocal()) {
                        Logging.info("Found local class properties array, trying to resolve...");
                        resolveLocalClassProperties(arrayPtr, propertyCount, absEnv, classDef);
                    } else {
                        Logging.warn("Class properties array is neither global nor local: " + arrayPtr.getRegion().getClass().getSimpleName());
                    }
                    continue;
                }
                
                // 全局属性描述符数组的情况
                long arrayAddr = arrayPtr.getValue();
                
                if (ModuleInitChecker.isValidMemoryAddress(arrayAddr, "class properties array")) {
                    Logging.info("Found valid global class properties array at: 0x" + Long.toHexString(arrayAddr));
                    resolveGlobalClassProperties(arrayAddr, propertyCount, classDef);
                } else {
                    Logging.warn("Invalid global properties array address for class: " + classDef.className);
                }
            }
        } catch (Exception e) {
            Logging.error("Exception in resolveClassProperties: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 解析全局类属性描述符数组 - 增加验证
     */
    private void resolveGlobalClassProperties(long ptr, int propertyCount, ClassDefinition classDef) {
        int ptrSize = hust.cse.ohnapisummary.util.MyGlobalState.defaultPointerSize;
        int structSize = ptrSize * 8; // napi_property_descriptor结构体大小
        
        Logging.info("Resolving global class properties for " + classDef.className + 
                    ", array at 0x" + Long.toHexString(ptr) + ", count: " + propertyCount);

        for (int i = 0; i < propertyCount; i++) {
            long structAddr = ptr + i * structSize;
            
            // 验证结构体地址
            if (!ModuleInitChecker.validateNAPIDescriptorStructure(ptr, i, "class properties")) {
                Logging.warn("Property descriptor validation failed for " + classDef.className + "[" + i + "]");
                continue;
            }
            
            try {
                Address base = GlobalState.flatAPI.toAddr(structAddr);

                // 解析属性名（utf8name字段）
                Address utf8nameAddr = base.add(ptrSize * 0);
                long namePtr = ModuleInitChecker.getValueFromAddrWithPtrSize(utf8nameAddr.getOffset(), ptrSize);
                String propertyName = null;
                
                if (namePtr != 0 && ModuleInitChecker.isValidMemoryAddress(namePtr, "class property name")) {
                    propertyName = ModuleInitChecker.getStrFromAddr(namePtr);
                }

                if (propertyName != null) {
                    PropertyDescriptor propDesc = new PropertyDescriptor(propertyName);

                    // 解析方法指针（method字段）
                    Address methodAddr = base.add(ptrSize * 2);
                    long methodPtrValue = ModuleInitChecker.getValueFromAddrWithPtrSize(methodAddr.getOffset(), ptrSize);
                    if (methodPtrValue != 0 && ModuleInitChecker.isValidMemoryAddress(methodPtrValue, "class method ptr")) {
                        propDesc.methodPtr = methodPtrValue;
                    }

                    // 解析getter指针（getter字段）
                    Address getterAddr = base.add(ptrSize * 3);
                    long getterPtrValue = ModuleInitChecker.getValueFromAddrWithPtrSize(getterAddr.getOffset(), ptrSize);
                    if (getterPtrValue != 0 && ModuleInitChecker.isValidMemoryAddress(getterPtrValue, "class getter ptr")) {
                        propDesc.getterPtr = getterPtrValue;
                    }

                    // 解析setter指针（setter字段）
                    Address setterAddr = base.add(ptrSize * 4);
                    long setterPtrValue = ModuleInitChecker.getValueFromAddrWithPtrSize(setterAddr.getOffset(), ptrSize);
                    if (setterPtrValue != 0 && ModuleInitChecker.isValidMemoryAddress(setterPtrValue, "class setter ptr")) {
                        propDesc.setterPtr = setterPtrValue;
                    }

                    if (propDesc.methodPtr != null || propDesc.getterPtr != null || propDesc.setterPtr != null) {
                        classDef.properties.put(propertyName, propDesc);
                        Logging.info("Validated class property: " + classDef.className + "." + propertyName +
                            " (method: " + (propDesc.methodPtr != null ? "0x" + Long.toHexString(propDesc.methodPtr) : "null") +
                            ", getter: " + (propDesc.getterPtr != null ? "0x" + Long.toHexString(propDesc.getterPtr) : "null") +
                            ", setter: " + (propDesc.setterPtr != null ? "0x" + Long.toHexString(propDesc.setterPtr) : "null") + ")");
                    } else {
                        Logging.warn("No valid method pointers found for class property: " + propertyName);
                    }
                } else {
                    Logging.warn("Failed to resolve property name for " + classDef.className + "[" + i + "]");
                }
            } catch (Exception e) {
                Logging.error("Exception parsing class property " + i + " for " + classDef.className + ": " + e.getMessage());
            }
        }
    }
    
    /**
     * 解析栈上的类属性描述符数组
     */
    private void resolveLocalClassProperties(AbsVal arrayPtr, int propertyCount, AbsEnv absEnv, ClassDefinition classDef) {
        RegionBase region = arrayPtr.getRegion();
        long baseOffset = arrayPtr.getValue();
        int ptrSize = hust.cse.ohnapisummary.util.MyGlobalState.defaultPointerSize;
        int structSize = ptrSize * 8; // napi_property_descriptor结构体大小
        
        Logging.info("Resolving local class properties array, base offset: " + baseOffset + ", count: " + propertyCount);
        
        for (int i = 0; i < propertyCount; i++) {
            long structOffset = baseOffset + i * structSize;
            
            // 解析属性名
            String propertyName = resolveLocalDescriptorField(region, structOffset + ptrSize * 0, absEnv);
            
            if (propertyName != null) {
                PropertyDescriptor propDesc = new PropertyDescriptor(propertyName);
                
                // 解析方法指针
                Long methodPtr = resolveLocalDescriptorMethodPtr(region, structOffset + ptrSize * 2, absEnv);
                if (methodPtr != null && methodPtr != 0) {
                    propDesc.methodPtr = methodPtr;
                }
                
                // 解析getter指针
                Long getterPtr = resolveLocalDescriptorMethodPtr(region, structOffset + ptrSize * 3, absEnv);
                if (getterPtr != null && getterPtr != 0) {
                    propDesc.getterPtr = getterPtr;
                }
                
                // 解析setter指针
                Long setterPtr = resolveLocalDescriptorMethodPtr(region, structOffset + ptrSize * 4, absEnv);
                if (setterPtr != null && setterPtr != 0) {
                    propDesc.setterPtr = setterPtr;
                }
                
                classDef.properties.put(propertyName, propDesc);
                Logging.info("Found local class property: " + propertyName + 
                    " (method: " + (propDesc.methodPtr != null ? "0x" + Long.toHexString(propDesc.methodPtr) : "null") +
                    ", getter: " + (propDesc.getterPtr != null ? "0x" + Long.toHexString(propDesc.getterPtr) : "null") +
                    ", setter: " + (propDesc.setterPtr != null ? "0x" + Long.toHexString(propDesc.setterPtr) : "null") + ")");
            } else {
                Logging.warn("Failed to resolve local class property at offset: " + structOffset);
            }
        }
    }
    
    /**
     * 获取所有类定义
     */
    public Map<String, ClassDefinition> getAllClassDefinitions() {
        return classDefinitions;
    }
    
    // 工具方法 - 使用ModuleInitChecker的增强解析功能
    private String extractString(KSet kSet, AbsEnv absEnv, String context) {
        return ModuleInitChecker.resolveStringFromKSet(kSet, absEnv, context);
    }
    
    private Long extractValue(KSet kSet, AbsEnv absEnv, String context) {
        return ModuleInitChecker.resolveLongFromKSet(kSet, absEnv, context);
    }
    
    /**
     * 带诊断信息的字符串解析
     */
    private String extractStringWithDiagnostics(KSet kSet, AbsEnv absEnv, String context, int paramIndex) {
        Logging.debug("Extracting string for parameter " + paramIndex + " (" + context + ")");
        
        if (kSet == null) {
            Logging.warn("KSet is null for parameter " + paramIndex + " (" + context + ")");
            return null;
        }
        
        try {
            return ModuleInitChecker.resolveStringFromKSet(kSet, absEnv, context);
        } catch (Exception e) {
            Logging.error("Failed to extract string for parameter " + paramIndex + ": " + e.getMessage());
            // 尝试备用方法
            return tryAlternativeStringExtraction(kSet, paramIndex, context);
        }
    }
    
    /**
     * 带诊断信息的数值解析
     */
    private Long extractValueWithDiagnostics(KSet kSet, AbsEnv absEnv, String context, int paramIndex) {
        Logging.debug("Extracting value for parameter " + paramIndex + " (" + context + ")");
        
        if (kSet == null) {
            Logging.warn("KSet is null for parameter " + paramIndex + " (" + context + ")");
            return null;
        }
        
        try {
            return ModuleInitChecker.resolveLongFromKSet(kSet, absEnv, context);
        } catch (Exception e) {
            Logging.error("Failed to extract value for parameter " + paramIndex + ": " + e.getMessage());
            // 尝试备用方法
            return tryAlternativeValueExtraction(kSet, paramIndex, context);
        }
    }
    
    /**
     * 备用字符串提取方法
     */
    private String tryAlternativeStringExtraction(KSet kSet, int paramIndex, String context) {
        try {
            Logging.info("Trying alternative string extraction for parameter " + paramIndex);
            
            // 方法1：检查KSet的toString()输出
            String ksetStr = kSet.toString();
            Logging.debug("KSet toString: " + ksetStr);
            
            // 方法2：尝试直接访问内部字段（如果可能）
            // 这可能需要反射或其他方法
            
            // 方法3：使用不同的参数索引重试
            if (paramIndex > 0) {
                Logging.debug("Attempting parameter index adjustment...");
                // 可以尝试paramIndex-1或paramIndex+1
            }
            
        } catch (Exception e) {
            Logging.debug("Alternative extraction also failed: " + e.getMessage());
        }
        
        return null;
    }
    
    /**
     * 备用数值提取方法
     */
    private Long tryAlternativeValueExtraction(KSet kSet, int paramIndex, String context) {
        try {
            Logging.info("Trying alternative value extraction for parameter " + paramIndex);
            
            // 类似的备用策略
            String ksetStr = kSet.toString();
            Logging.debug("KSet toString: " + ksetStr);
            
            // 可以尝试从字符串表示中解析数值
            if (ksetStr.contains("Global")) {
                // 尝试提取地址信息
                Logging.debug("Found Global reference in KSet");
            }
            
        } catch (Exception e) {
            Logging.debug("Alternative value extraction also failed: " + e.getMessage());
        }
        
        return null;
    }
    
    private String resolveLocalDescriptorField(RegionBase region, long fieldOffset, AbsEnv absEnv) {
        ALoc fieldLoc = ALoc.getALoc(region, fieldOffset, hust.cse.ohnapisummary.util.MyGlobalState.defaultPointerSize);
        KSet fieldKSet = absEnv.get(fieldLoc);
        
        // 使用增强的字符串解析功能
        return ModuleInitChecker.resolveStringFromKSet(fieldKSet, absEnv, "local class property field");
    }
    
    private Long resolveLocalDescriptorMethodPtr(RegionBase region, long fieldOffset, AbsEnv absEnv) {
        ALoc fieldLoc = ALoc.getALoc(region, fieldOffset, hust.cse.ohnapisummary.util.MyGlobalState.defaultPointerSize);
        KSet fieldKSet = absEnv.get(fieldLoc);
        
        // 使用增强的值解析功能
        return ModuleInitChecker.resolveLongFromKSet(fieldKSet, absEnv, "local class property method ptr");
    }
}
