package hust.cse.ohnapisummary.checkers;

import com.bai.checkers.CheckerBase;
import com.bai.env.*;
import com.bai.env.region.RegionBase;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import hust.cse.ohnapisummary.mapping.NAPIDescriptor;
import hust.cse.ohnapisummary.util.MyGlobalState;
import hust.cse.ohnapisummary.util.NAPIValue;

import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 模块初始化检查器 - 负责解析动态注册的NAPI函数
 * 重构后采用专门的解析器处理不同的注册模式：
 * 1. PropertyRegistrationResolver - 处理 napi_define_properties
 * 2. ClassRegistrationResolver - 处理 napi_define_class
 * 3. FunctionRegistrationResolver - 处理 napi_create_function + napi_set_named_property
 */
public class ModuleInitChecker extends CheckerBase {
    
    // 专门的解析器
    private final PropertyRegistrationResolver propertyResolver = new PropertyRegistrationResolver();
    private final ClassRegistrationResolver classResolver = new ClassRegistrationResolver();
    private final FunctionRegistrationResolver functionResolver = new FunctionRegistrationResolver();
    
    /**
     * 动态注册分析结果数据结构
     */
    public static class NAPIAnalysisResult {
        public String soName;
        public String moduleName;
        public List<PropertyRegistration> propertyRegistrations = new ArrayList<>();
        public List<ClassRegistration> classRegistrations = new ArrayList<>();
        public List<FunctionRegistration> functionRegistrations = new ArrayList<>();
        public AnalysisStatistics statistics = new AnalysisStatistics();
    }
    
    public static class PropertyRegistration {
        public String propertyName;
        public String address;
        public String resolvedFrom; // "memcpy", "direct_array", "local_array"
    }
    
    public static class ClassRegistration {
        public String className;
        public Constructor constructor;
        public List<Method> methods = new ArrayList<>();
        public List<Property> properties = new ArrayList<>();
        
        public static class Constructor {
            public String address;
        }
        
        public static class Method {
            public String methodName;
            public String address;
            public String type; // "method", "getter", "setter"
        }
        
        public static class Property {
            public String propertyName;
            public String methodAddress;
            public String getterAddress;
            public String setterAddress;
        }
    }
    
    public static class FunctionRegistration {
        public String functionName;
        public String address;
        public String registrationMethod; // "create_function", "batch_registration"
    }
    
    public static class AnalysisStatistics {
        public int totalNAPICallsProcessed;
        public int successfullyProcessed;
        public int totalRegistrationsFound;
        public int propertyRegistrationsCount;
        public int classRegistrationsCount;
        public int functionRegistrationsCount;
        public String analysisTimestamp;
    }
    
    public ModuleInitChecker(String cwe, String version) {
        super(cwe, version);
    }

    @Override
    public boolean check() {
        Logging.info("=== Starting ModuleInitChecker with enhanced resolvers ===");
        Logging.info("SO Name: " + (MyGlobalState.soName != null ? MyGlobalState.soName : "unknown"));
        Logging.info("Module Name: " + (MyGlobalState.moduleName != null ? MyGlobalState.moduleName : "unknown"));
        
        try {
            // 第一轮：解析所有NAPI调用
            Logging.info("Phase 1: Processing NAPI function calls...");
            processNAPIFunctionCalls();
            
            // 第二轮：处理属性名称赋值（napi_set_named_property）
            Logging.info("Phase 2: Processing property name assignments...");
            processPropertyNameAssignments();
            
            // 第三轮：生成最终的动态注册函数列表
            Logging.info("Phase 3: Generating final registrations...");
            generateFinalRegistrations();
            
            // 第四轮：导出解析结果到JSON文件
            Logging.info("Phase 4: Exporting analysis results...");
            exportRegistrationResults();
            
            Logging.info("=== ModuleInitChecker analysis completed successfully ===");
            
        } catch (Exception e) {
            Logging.error("ModuleInitChecker execution failed: " + e.getMessage());
            e.printStackTrace();
            // 即使出现异常，也尝试导出已解析的部分结果
            try {
                Logging.info("Attempting to export partial results...");
                exportRegistrationResults();
            } catch (Exception exportEx) {
                Logging.error("Failed to export partial results: " + exportEx.getMessage());
            }
        }
        
        return false;
    }
    
    /**
     * 处理所有NAPI函数调用
     */
    private void processNAPIFunctionCalls() {
        int totalProcessed = 0;
        int successfullyProcessed = 0;
        
        for (Map.Entry<NAPIValue, Context> entry : MyGlobalState.napiManager.callsOrValues.entrySet()) {
            totalProcessed++;
            
            try {
                NAPIValue napiValue = entry.getKey();
                Context context = entry.getValue();
                Function callee = napiValue.getApi();
                
                if (callee == null) {
                    Logging.error("Cannot find called external function for 0x" + Long.toHexString(napiValue.callSite));
                    continue;
                }
                
                String calleeName = callee.getName();
                AbsEnv absEnv = context.getAbsEnvIn().get(GlobalState.flatAPI.toAddr(napiValue.callSite));
                
                if (absEnv == null) {
                    Logging.error("Cannot find absEnv for 0x" + Long.toHexString(napiValue.callSite));
                    continue;
                }
                
                // 根据不同的NAPI函数类型分发给专门的解析器
                switch (calleeName) {
                    case "napi_define_properties":
                        try {
                            propertyResolver.processDefineProperties(callee, absEnv, 
                                GlobalState.flatAPI.getFunctionContaining(GlobalState.flatAPI.toAddr(napiValue.callSite)));
                            successfullyProcessed++;
                        } catch (Exception e) {
                            Logging.error("Failed to process napi_define_properties at 0x" + 
                                Long.toHexString(napiValue.callSite) + ": " + e.getMessage());
                        }
                        break;
                    case "napi_define_class":
                        try {
                            classResolver.processDefineClass(callee, absEnv, context);
                            successfullyProcessed++;
                        } catch (Exception e) {
                            Logging.error("Failed to process napi_define_class at 0x" + 
                                Long.toHexString(napiValue.callSite) + ": " + e.getMessage());
                        }
                        break;
                    case "napi_create_function":
                        try {
                            functionResolver.processCreateFunction(callee, absEnv, context);
                            successfullyProcessed++;
                        } catch (Exception e) {
                            Logging.error("Failed to process napi_create_function at 0x" + 
                                Long.toHexString(napiValue.callSite) + ": " + e.getMessage());
                        }
                        break;
                    default:
                        // 忽略其他NAPI函数调用
                        break;
                }
            } catch (Exception e) {
                Logging.error("Unexpected error processing NAPI call: " + e.getMessage());
                e.printStackTrace();
            }
        }
        
        Logging.info("NAPI function calls processing completed: " + successfullyProcessed + "/" + totalProcessed + " successful");
    }
    
    /**
     * 处理属性名称赋值（napi_set_named_property）
     */
    private void processPropertyNameAssignments() {
        for (Map.Entry<NAPIValue, Context> entry : MyGlobalState.napiManager.callsOrValues.entrySet()) {
            NAPIValue napiValue = entry.getKey();
            Context context = entry.getValue();
            Function callee = napiValue.getApi();
            
            if (callee != null && "napi_set_named_property".equals(callee.getName())) {
                AbsEnv absEnv = context.getAbsEnvIn().get(GlobalState.flatAPI.toAddr(napiValue.callSite));
                if (absEnv != null) {
                    functionResolver.processSetNamedProperty(callee, absEnv, context);
                }
            }
        }
    }
    
    /**
     * 生成最终的动态注册函数列表
     */
    private void generateFinalRegistrations() {
        // 添加属性注册的函数
        propertyResolver.getAllPropertyRegistrations().forEach((name, ptr) -> {
            Logging.info("Find dynamic registered napi property function: " + name + " at 0x" + Long.toHexString(ptr));
            MyGlobalState.dynRegNAPIList.add(new NAPIDescriptor(name, GlobalState.flatAPI.toAddr(ptr)));
        });
        
        // 添加普通函数注册
        functionResolver.getAllFunctionRegistrations().forEach((name, funcReg) -> {
            Logging.info("Find dynamic registered napi function: " + name + " at 0x" + Long.toHexString(funcReg.functionPtr));
            MyGlobalState.dynRegNAPIList.add(new NAPIDescriptor(name, GlobalState.flatAPI.toAddr(funcReg.functionPtr)));
        });
        
        // 添加类相关注册
        classResolver.getAllClassDefinitions().forEach((className, classDef) -> {
            addClassRegistrations(classDef);
        });
        
        // 输出统计信息
        Logging.info("Total dynamic NAPI registrations found: " + MyGlobalState.dynRegNAPIList.size());
    }
    
    /**
     * 添加类相关的注册信息
     */
    private void addClassRegistrations(ClassRegistrationResolver.ClassDefinition classDef) {
        // 注册构造函数
        if (classDef.constructorPtr != null) {
            String constructorName = classDef.className + "::constructor";
            Logging.info("Find class constructor: " + constructorName + " at 0x" + Long.toHexString(classDef.constructorPtr));
            MyGlobalState.dynRegNAPIList.add(new NAPIDescriptor(constructorName, GlobalState.flatAPI.toAddr(classDef.constructorPtr)));
        }
        
        // 注册属性方法
        classDef.properties.forEach((propName, prop) -> {
            String classPrefix = classDef.className + "::";
            
            if (prop.methodPtr != null) {
                String methodName = classPrefix + prop.propertyName;
                Logging.info("Find class method: " + methodName + " at 0x" + Long.toHexString(prop.methodPtr));
                MyGlobalState.dynRegNAPIList.add(new NAPIDescriptor(methodName, GlobalState.flatAPI.toAddr(prop.methodPtr)));
            }
            
            if (prop.getterPtr != null) {
                String getterName = classPrefix + "get_" + prop.propertyName;
                Logging.info("Find class getter: " + getterName + " at 0x" + Long.toHexString(prop.getterPtr));
                MyGlobalState.dynRegNAPIList.add(new NAPIDescriptor(getterName, GlobalState.flatAPI.toAddr(prop.getterPtr)));
            }
            
            if (prop.setterPtr != null) {
                String setterName = classPrefix + "set_" + prop.propertyName;
                Logging.info("Find class setter: " + setterName + " at 0x" + Long.toHexString(prop.setterPtr));
                MyGlobalState.dynRegNAPIList.add(new NAPIDescriptor(setterName, GlobalState.flatAPI.toAddr(prop.setterPtr)));
            }
        });
    }
    
    /**
     * 导出解析结果到JSON文件
     */
    private void exportRegistrationResults() {
        try {
            Logging.info("Starting NAPI analysis results export...");
            
            NAPIAnalysisResult result = buildAnalysisResult();
            
            Logging.info("Built analysis result with " + result.statistics.totalRegistrationsFound + " total registrations");
            Logging.info("- Property registrations: " + result.statistics.propertyRegistrationsCount);
            Logging.info("- Class registrations: " + result.statistics.classRegistrationsCount);  
            Logging.info("- Function registrations: " + result.statistics.functionRegistrationsCount);
            
            // 生成JSON文件路径
            String outputPath = generateOutputPath();
            
            // 导出JSON
            Gson gson = new GsonBuilder()
                .setPrettyPrinting()
                .create();
            
            try (FileWriter writer = new FileWriter(outputPath)) {
                String jsonString = gson.toJson(result);
                writer.write(jsonString);
                writer.flush();
                
                Logging.info("✓ NAPI analysis results successfully exported to: " + outputPath);
                Logging.info("✓ File size: " + jsonString.length() + " characters");
                Logging.info("✓ Total registrations found: " + result.statistics.totalRegistrationsFound);
                
            } catch (IOException e) {
                Logging.error("✗ Failed to write NAPI analysis results: " + e.getMessage());
                e.printStackTrace();
            }
            
        } catch (Exception e) {
            Logging.error("✗ Failed to export NAPI analysis results: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 构建分析结果对象
     */
    private NAPIAnalysisResult buildAnalysisResult() {
        NAPIAnalysisResult result = new NAPIAnalysisResult();
        
        // 基本信息
        result.soName = MyGlobalState.soName != null ? MyGlobalState.soName : "unknown";
        result.moduleName = MyGlobalState.moduleName != null ? MyGlobalState.moduleName : "unknown";
        
        // 属性注册
        propertyResolver.getAllPropertyRegistrations().forEach((name, ptr) -> {
            PropertyRegistration propReg = new PropertyRegistration();
            propReg.propertyName = name;
            propReg.address = "0x" + Long.toHexString(ptr);
            propReg.resolvedFrom = "napi_define_properties";
            result.propertyRegistrations.add(propReg);
        });
        
        // 类注册
        classResolver.getAllClassDefinitions().forEach((className, classDef) -> {
            ClassRegistration classReg = new ClassRegistration();
            classReg.className = className;
            
            // 构造函数
            if (classDef.constructorPtr != null) {
                classReg.constructor = new ClassRegistration.Constructor();
                classReg.constructor.address = "0x" + Long.toHexString(classDef.constructorPtr);
            }
            
            // 属性方法
            classDef.properties.forEach((propName, prop) -> {
                ClassRegistration.Property property = new ClassRegistration.Property();
                property.propertyName = propName;
                
                if (prop.methodPtr != null) {
                    property.methodAddress = "0x" + Long.toHexString(prop.methodPtr);
                    
                    ClassRegistration.Method method = new ClassRegistration.Method();
                    method.methodName = propName;
                    method.address = property.methodAddress;
                    method.type = "method";
                    classReg.methods.add(method);
                }
                
                if (prop.getterPtr != null) {
                    property.getterAddress = "0x" + Long.toHexString(prop.getterPtr);
                    
                    ClassRegistration.Method getter = new ClassRegistration.Method();
                    getter.methodName = "get_" + propName;
                    getter.address = property.getterAddress;
                    getter.type = "getter";
                    classReg.methods.add(getter);
                }
                
                if (prop.setterPtr != null) {
                    property.setterAddress = "0x" + Long.toHexString(prop.setterPtr);
                    
                    ClassRegistration.Method setter = new ClassRegistration.Method();
                    setter.methodName = "set_" + propName;
                    setter.address = property.setterAddress;
                    setter.type = "setter";
                    classReg.methods.add(setter);
                }
                
                classReg.properties.add(property);
            });
            
            result.classRegistrations.add(classReg);
        });
        
        // 函数注册
        functionResolver.getAllFunctionRegistrations().forEach((name, funcReg) -> {
            FunctionRegistration funcRegJson = new FunctionRegistration();
            funcRegJson.functionName = name;
            funcRegJson.address = "0x" + Long.toHexString(funcReg.functionPtr);
            funcRegJson.registrationMethod = "napi_create_function";
            result.functionRegistrations.add(funcRegJson);
        });
        
        // 统计信息
        result.statistics.propertyRegistrationsCount = result.propertyRegistrations.size();
        result.statistics.classRegistrationsCount = result.classRegistrations.size();
        result.statistics.functionRegistrationsCount = result.functionRegistrations.size();
        result.statistics.totalRegistrationsFound = 
            result.statistics.propertyRegistrationsCount + 
            result.statistics.classRegistrationsCount + 
            result.statistics.functionRegistrationsCount;
        result.statistics.analysisTimestamp = java.time.Instant.now().toString();
        
        return result;
    }
    
    /**
     * 生成输出文件路径
     */
    private String generateOutputPath() {
        String basePath = MyGlobalState.soName != null ? MyGlobalState.soName : "unknown";
        if (basePath.endsWith(".so")) {
            basePath = basePath.substring(0, basePath.length() - 3);
        }
        
        // 生成到当前工作目录，方便查找
        String outputFileName = basePath + ".napi_analysis.json";
        String currentDir = System.getProperty("user.dir");
        String fullPath = Paths.get(currentDir, outputFileName).toString();
        
        Logging.info("NAPI analysis results will be exported to: " + fullPath);
        return fullPath;
    }
    
    // ====== 静态工具方法 ======
    
    /**
     * 增强的字符串解析 - 支持local变量解析
     * 参考NapiGetCallBackInfo中数字解析的模式
     */
    public static String resolveStringFromKSet(KSet ks, AbsEnv absEnv, String context) {
        if (ks == null || ks.isBot()) {
            Logging.warn("KSet is null or bot in " + context);
            return null;
        }
        
        try {
            for (AbsVal val : ks) {
                // 首先尝试全局常量字符串
                if (val.getRegion().isGlobal()) {
                    long addr = val.getValue();
                    String globalStr = getStrFromAddr(addr);
                    if (globalStr != null) {
                        Logging.info("Resolved global string in " + context + ": " + globalStr);
                        return globalStr;
                    }
                } else {
                    // 尝试解析local变量 - 参考NapiGetCallBackInfo的模式
                    try {
                        ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                        if (ptr != null && absEnv != null) {
                            KSet localKs = absEnv.get(ptr);
                            Logging.info("Attempting to resolve local string in " + context + ", ptr KSet: " + localKs);
                            
                            if (localKs != null && !localKs.isBot()) {
                                for (AbsVal localVal : localKs) {
                                    if (localVal.getRegion().isGlobal()) {
                                        long addr = localVal.getValue();
                                        String localStr = getStrFromAddr(addr);
                                        if (localStr != null) {
                                            Logging.info("Resolved local string in " + context + ": " + localStr);
                                            return localStr;
                                        }
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                        Logging.warn("Failed to resolve local string in " + context + ": " + e.getMessage());
                    }
                }
            }
        } catch (Exception e) {
            Logging.error("Exception while iterating KSet in " + context + ": " + e.getMessage());
            e.printStackTrace();
            return null;
        }
        
        Logging.warn("Could not resolve string from KSet in " + context);
        return null;
    }
    
    /**
     * 增强的数值解析 - 支持local变量解析
     * 参考NapiGetCallBackInfo中数字解析的模式
     */
    public static Long resolveLongFromKSet(KSet ks, AbsEnv absEnv, String context) {
        if (ks == null || ks.isBot()) {
            Logging.warn("KSet is null or bot in " + context);
            return null;
        }
        
        try {
            for (AbsVal val : ks) {
                // 首先尝试全局常量
                if (val.getRegion().isGlobal()) {
                    long value = val.getValue();
                    Logging.info("Resolved global long in " + context + ": " + value);
                    return value;
                } else {
                    // 尝试解析local变量 - 参考NapiGetCallBackInfo的模式
                    try {
                        ALoc ptr = toALoc(val, MyGlobalState.defaultPointerSize);
                        if (ptr != null && absEnv != null) {
                            KSet localKs = absEnv.get(ptr);
                            Logging.info("Attempting to resolve local long in " + context + ", ptr KSet: " + localKs);
                            
                            if (localKs != null && !localKs.isBot()) {
                                for (AbsVal localVal : localKs) {
                                    if (localVal.getRegion().isGlobal()) {
                                        long value = localVal.getValue();
                                        Logging.info("Resolved local long in " + context + ": " + value);
                                        return value;
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                        Logging.warn("Failed to resolve local long in " + context + ": " + e.getMessage());
                    }
                }
            }
        } catch (Exception e) {
            Logging.error("Exception while iterating KSet in " + context + ": " + e.getMessage());
            e.printStackTrace();
            return null;
        }
        
        Logging.warn("Could not resolve long from KSet in " + context);
        return null;
    }
    
    /**
     * 从内存地址读取字符串
     */
    public static String getStrFromAddr(long addr) {
        try {
            byte[] bs = getStringFromMemory(GlobalState.flatAPI.toAddr(addr));
            if (bs == null) return null;
            
            Charset csets = StandardCharsets.UTF_8;
            CharsetDecoder cd = csets.newDecoder();
            CharBuffer r = cd.decode(ByteBuffer.wrap(bs));
            return r.toString();
        } catch (MemoryAccessException | CharacterCodingException e) {
            Logging.error("String decode failed! 0x" + Long.toHexString(addr));
            return null;
        }
    }
    
    /**
     * 将AbsVal转换为ALoc - 参考NapiGetCallBackInfo的实现
     */
    public static ALoc toALoc(AbsVal val, int pointerSize) {
        RegionBase region = val.getRegion();
        long begin = val.getValue();
        return ALoc.getALoc(region, begin, pointerSize);
    }
    
    /**
     * 从内存读取以null结尾的字符串
     */
    public static byte[] getStringFromMemory(Address addr) throws MemoryAccessException {
        MemoryBlock mb = GlobalState.currentProgram.getMemory().getBlock(addr);
        if (mb == null) {
            Logging.error("Cannot decode string at 0x" + addr.toString());
            return null;
        }
        
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while(mb.getByte(addr) != 0) {
            out.write(mb.getByte(addr));
            addr = addr.add(1);
        }
        return out.toByteArray();
    }
    
    /**
     * 从指定地址读取指针大小的值
     */
    public static long getValueFromAddrWithPtrSize(long addr, int ptrSize) {
        Address address = GlobalState.flatAPI.toAddr(addr);
        Memory memory = GlobalState.currentProgram.getMemory();
        
        try {
            if (ptrSize == 4) {
                return memory.getInt(address) & 0xFFFFFFFFL;
            } else if (ptrSize == 8) {
                return memory.getLong(address);
            } else {
                Logging.error("Unsupported pointer size: " + ptrSize);
                return 0;
            }
        } catch (MemoryAccessException e) {
            Logging.error("Failed to read value from 0x" + Long.toHexString(addr) + ": " + e.getMessage());
            return 0;
        }
    }
}
