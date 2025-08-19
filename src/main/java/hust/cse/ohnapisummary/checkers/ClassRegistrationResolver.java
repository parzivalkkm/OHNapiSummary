package hust.cse.ohnapisummary.checkers;

import com.bai.env.*;
import com.bai.env.region.RegionBase;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;
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
            // 解析类名（第2个参数）
            KSet classNameKSet = CheckerBase.getParamKSet(callee, 1, absEnv);
            String className = extractGlobalString(classNameKSet, absEnv, "class name in napi_define_class");
            
            // 解析构造函数指针（第4个参数）
            KSet constructorKSet = CheckerBase.getParamKSet(callee, 3, absEnv);
            Long constructorPtr = extractGlobalValue(constructorKSet, absEnv, "constructor ptr in napi_define_class");
            
            // 解析属性数量（第6个参数）
            KSet propertyCountKSet = CheckerBase.getParamKSet(callee, 5, absEnv);
            Long propertyCountLong = extractGlobalValue(propertyCountKSet, absEnv, "property count in napi_define_class");
            long propertyCount = (propertyCountLong != null) ? propertyCountLong : 0;
            
            // 解析属性描述符数组（第7个参数）
            KSet propertiesKSet = CheckerBase.getParamKSet(callee, 6, absEnv);
            
            if (className != null && constructorPtr != null) {
                Logging.info("Found class definition: " + className + " with constructor at 0x" + Long.toHexString(constructorPtr));
                ClassDefinition classDef = new ClassDefinition(className, constructorPtr);
                
                // 解析属性描述符
                if (propertyCount > 0 && propertiesKSet != null) {
                    resolveClassProperties(propertiesKSet, (int) propertyCount, absEnv, classDef);
                }
                
                classDefinitions.put(className, classDef);
            } else {
                Logging.warn("Failed to resolve class definition - className: " + className + ", constructorPtr: " + constructorPtr);
            }
        } catch (Exception e) {
            Logging.error("Exception in processDefineClass: " + e.getMessage());
            e.printStackTrace();
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
                Logging.info("Found global class properties array at: 0x" + Long.toHexString(arrayAddr));
                resolveGlobalClassProperties(arrayAddr, propertyCount, classDef);
            }
        } catch (Exception e) {
            Logging.error("Exception in resolveClassProperties: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 解析全局类属性描述符数组
     */
    private void resolveGlobalClassProperties(long ptr, int propertyCount, ClassDefinition classDef) {
        int ptrSize = hust.cse.ohnapisummary.util.MyGlobalState.defaultPointerSize;
        int structSize = ptrSize * 8; // napi_property_descriptor结构体大小
        
        for (int i = 0; i < propertyCount; i++) {
            Address base = GlobalState.flatAPI.toAddr(ptr + i * structSize);

            // 解析属性名（utf8name字段）
            Address utf8nameAddr = base.add(ptrSize * 0);
            Address utf8nameTrueAddr = GlobalState.flatAPI.toAddr(
                ModuleInitChecker.getValueFromAddrWithPtrSize(utf8nameAddr.getOffset(), ptrSize));
            String propertyName = ModuleInitChecker.getStrFromAddr(utf8nameTrueAddr.getOffset());

            if (propertyName != null) {
                PropertyDescriptor propDesc = new PropertyDescriptor(propertyName);

                // 解析方法指针（method字段）
                Address methodAddr = base.add(ptrSize * 2);
                long methodPtrValue = ModuleInitChecker.getValueFromAddrWithPtrSize(methodAddr.getOffset(), ptrSize);
                if (methodPtrValue != 0) {
                    propDesc.methodPtr = methodPtrValue;
                }

                // 解析getter指针（getter字段）
                Address getterAddr = base.add(ptrSize * 3);
                long getterPtrValue = ModuleInitChecker.getValueFromAddrWithPtrSize(getterAddr.getOffset(), ptrSize);
                if (getterPtrValue != 0) {
                    propDesc.getterPtr = getterPtrValue;
                }

                // 解析setter指针（setter字段）
                Address setterAddr = base.add(ptrSize * 4);
                long setterPtrValue = ModuleInitChecker.getValueFromAddrWithPtrSize(setterAddr.getOffset(), ptrSize);
                if (setterPtrValue != 0) {
                    propDesc.setterPtr = setterPtrValue;
                }

                classDef.properties.put(propertyName, propDesc);
                Logging.info("Found class property: " + propertyName +
                    " (method: " + (propDesc.methodPtr != null ? "0x" + Long.toHexString(propDesc.methodPtr) : "null") +
                    ", getter: " + (propDesc.getterPtr != null ? "0x" + Long.toHexString(propDesc.getterPtr) : "null") +
                    ", setter: " + (propDesc.setterPtr != null ? "0x" + Long.toHexString(propDesc.setterPtr) : "null") + ")");
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
    private String extractGlobalString(KSet kSet, AbsEnv absEnv, String context) {
        return ModuleInitChecker.resolveStringFromKSet(kSet, absEnv, context);
    }
    
    private Long extractGlobalValue(KSet kSet, AbsEnv absEnv, String context) {
        return ModuleInitChecker.resolveLongFromKSet(kSet, absEnv, context);
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
