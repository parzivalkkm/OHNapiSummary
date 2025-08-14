package hust.cse.ohnapisummary.checkers;

import com.bai.checkers.CheckerBase;
import com.bai.env.*;
import com.bai.env.region.RegionBase;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import hust.cse.ohnapisummary.ir.value.Str;
import hust.cse.ohnapisummary.mapping.NAPIDescriptor;
import hust.cse.ohnapisummary.util.MyGlobalState;
import hust.cse.ohnapisummary.util.NAPIValue;
import hust.cse.ohnapisummary.util.NAPIValueManager;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ModuleInitChecker extends CheckerBase {
    public ModuleInitChecker(String cwe, String version) {
        super(cwe, version);
    }

    // 用于记录函数地址和对应的napi_value的映射
    private Map<NAPIValue, Long> valueToFunctionPointerMap = new HashMap<>();

    private Map<String, Long> name2FunctionPointerMap = new HashMap<>();


    @Override
    public boolean check() {
        Logging.info("Checking Module Init Function");
        for (Map.Entry<NAPIValue, Context> entry : MyGlobalState.napiManager.callsOrValues.entrySet()) {
            NAPIValue napiValue = entry.getKey();
            Context context = entry.getValue();
            long callSite = napiValue.callSite;
            Function caller = GlobalState.flatAPI.getFunctionContaining(GlobalState.flatAPI.toAddr(callSite));
            Function callee = napiValue.getApi();
            if (callee == null) {
                Logging.error("Cannot find called external function for 0x" + Long.toHexString(callSite));
                continue;
            }

            String calleeName = callee.getName();

            if (calleeName.equals("napi_define_properties")) {
                Logging.info("Resolving dynamic registered napi from napi_define_properties");
                AbsEnv absEnv = context.getAbsEnvIn().get(GlobalState.flatAPI.toAddr(callSite));
                if (absEnv == null) {
                    Logging.error("Cannot find absEnv for 0x" + Long.toHexString(callSite));
                    continue;
                }

                // 解析napi_define_properties的第三个参数,即napi_property_descriptor数组的长度
                KSet sizeKSet = getParamKSet(callee, 2, absEnv);
                long size = 0;
                for (AbsVal absVal : sizeKSet) {
                    if (absVal.getRegion().isGlobal()) {
                        size = absVal.getValue();
                    }
                }
                Logging.info("size of descriptors is: " + size);

                // 解析napi_define_properties的第四个参数，即napi_property_descriptor数组的指针
                KSet descriptorArrayKSet = getParamKSet(callee, 3, absEnv);
                
                // 尝试从memcpy解析（用于大量函数的情况）
                boolean resolvedFromMemcpy = directlyResolveDyRegFromMemcpyParam(caller, (int) size);
                
                // 如果memcpy方式失败，尝试直接解析descriptor数组（用于少量函数的情况）
                if (!resolvedFromMemcpy) {
                    Logging.info("Memcpy approach failed, trying direct descriptor array resolution");
                    directlyResolveFromDescriptorArray(descriptorArrayKSet, (int) size, absEnv);
                }

            }else if (calleeName.equals("napi_create_function")) {
                if (!(napiValue.isLocalValue() && napiValue.getRetIntoParamIndex() == 5)) {
                    continue;
                }
                // 注册形如：
                // static napi_value Init(napi_env env, napi_value exports) {
                //    napi_value fn = nullptr;
                //    napi_create_function(env, nullptr, 0, CalculateArea, nullptr, &fn);
                //    napi_set_named_property(env, exports, "calculateArea", fn);
                //    return exports;
                //}
                Logging.info("Resolving dynamic registered napi from napi_create_function");

                AbsEnv absEnv = context.getAbsEnvIn().get(GlobalState.flatAPI.toAddr(callSite));
                if (absEnv == null) {
                    Logging.error("Cannot find absEnv for 0x" + Long.toHexString(callSite));
                    continue;
                }

                // 解析napi_create_function的第四个参数，即函数指针
                KSet funcPtrKSet = getParamKSet(callee, 3, absEnv);
                long funcPtr = 0;
                for (AbsVal absVal : funcPtrKSet) {
                    if (absVal.getRegion().isGlobal()) {
                        funcPtr = absVal.getValue();
                    }
                }
                Logging.info("function pointer is: " + funcPtr);

                valueToFunctionPointerMap.put(napiValue, funcPtr);
            }
        }


        // 对 set_named_property 进行处理
        for (Map.Entry<NAPIValue, Context> entry : MyGlobalState.napiManager.callsOrValues.entrySet()) {
            NAPIValue napiValue = entry.getKey();
            Context context = entry.getValue();
            long callSite = napiValue.callSite;
            Function caller = GlobalState.flatAPI.getFunctionContaining(GlobalState.flatAPI.toAddr(callSite));
            Function callee = napiValue.getApi();
            if (callee == null) {
                Logging.error("Cannot find called external function for 0x" + Long.toHexString(callSite));
                continue;
            }

            String calleeName = callee.getName();

            if (calleeName.equals("napi_set_named_property")) {
                // 注册形如：
                // static napi_value Init(napi_env env, napi_value exports) {
                //    napi_value fn = nullptr;
                //    napi_create_function(env, nullptr, 0, CalculateArea, nullptr, &fn);
                //    napi_set_named_property(env, exports, "calculateArea", fn);
                //    return exports;
                //}
                Logging.info("Resolving dynamic registered napi from napi_set_named_property");
                // 解析napi_set_named_property的第三个参数
                AbsEnv absEnv = context.getAbsEnvIn().get(GlobalState.flatAPI.toAddr(callSite));
                if (absEnv == null) {
                    Logging.error("Cannot find absEnv for 0x" + Long.toHexString(callSite));
                    continue;
                }

                // 解析napi_set_named_property的第三个参数，即属性名
                KSet nameKSet = getParamKSet(callee, 2, absEnv);
                String name = null;
                for (AbsVal absVal : nameKSet) {
                    if (absVal.getRegion().isGlobal()) {
                        name = decodeStr(absEnv, absVal);
                    } else {
                        Logging.error("name is not global.");
                    }
                }
                Logging.info("name of property is: " + name);

                // 解析napi_set_named_property的第四个参数，即属性值
                KSet valueKSet = getParamKSet(callee, 3, absEnv);
                Long id = null;
                for (AbsVal absVal : valueKSet) {
                    if (absVal.getRegion().isGlobal()) {
                        id = absVal.getValue();
                    }
                }
                if (id == null) {
                    Logging.error("Cannot find napi_value pointer.");
                    continue;
                }
                Logging.info("napi_value pointer is: " + id);

                Long funcPtr = null;

                // 这个值保存的可能是给不透明值分配的id
                if (NAPIValueManager.highestBitsMatch(id)) { // special value
                    NAPIValue v = MyGlobalState.napiManager.getValue(id);
                    if (v != null) {
                        funcPtr = valueToFunctionPointerMap.get(v);
                    }
                }


                if (name != null && funcPtr != null) {
                    name2FunctionPointerMap.put(name, funcPtr);
                }
            }
        }
        // TODO 处理第二种方式注册的函数
        // 遍历valueToFunctionPointerMap以及valueToFunctionNameMap，将其解析为NAPIDescriptor
        for(Map.Entry<String, Long>  entry1 : name2FunctionPointerMap.entrySet()){
            String functionName = entry1.getKey();
            long funcPtr = entry1.getValue();

            Logging.info("Find dynamic registered napi: " + functionName + " at 0x" + Long.toHexString(funcPtr));
            MyGlobalState.dynRegNAPIList.add(new NAPIDescriptor(functionName, GlobalState.flatAPI.toAddr(funcPtr)));

        }
        return false;
    }

    private boolean directlyResolveDyRegFromMemcpyParam(Function function,int size) {
        List<Reference> references = Utils.getReferences(List.of("memcpy"));
        if (references.isEmpty()) {
            Logging.warn("No memcpy references found.");
            return false;
        }
        
        boolean found = false;
        for (Reference reference : references) {
            Address toAddress = reference.getToAddress();
            Address fromAddress = reference.getFromAddress();
            Function callee = GlobalState.flatAPI.getFunctionAt(toAddress);
            Function caller = GlobalState.flatAPI.getFunctionContaining(fromAddress);
            Parameter[] params = callee.getParameters();

            if (callee == null || caller == null) {
                continue;
            }
            // 仅当此处调用是由function调用memcpy时，才进行处理
            if (!caller.getName().equals(function.getName())) {
                continue;
            }
            Logging.info(fromAddress + ": " + caller.getName() + " -> " + toAddress + ": " + callee.getName());

            // 获得其第二个参数的值
            Context context = Context.getContext(caller).iterator().next();
            AbsEnv absEnv = context.getAbsEnvIn().get(fromAddress);
            KSet srcPtrKSet = getParamKSet(callee, 1, absEnv);
            if (!srcPtrKSet.isNormal()) {
                Logging.error("srcPtrKSet is not normal.");
                continue;
            }
            if (!srcPtrKSet.isSingleton()) {
                Logging.error("srcPtrKSet is not singleton.");
                continue;
            }
            AbsVal srcPtr = srcPtrKSet.iterator().next();
            Logging.info("srcPtr: " + srcPtr.getValue());

            directlyResolveNAPIDescriptorsAt(srcPtr.getValue(),size);
            found = true;
        }
        return found;
    }

    /**
     * 直接从descriptor数组解析，适用于少量函数直接赋值的情况
     */
    private void directlyResolveFromDescriptorArray(KSet descriptorArrayKSet, int size, AbsEnv absEnv) {
        Logging.info("Resolving descriptors from direct array access");
        
        for (AbsVal arrayPtr : descriptorArrayKSet) {
            if (!arrayPtr.getRegion().isGlobal()) {
                // 可能是栈上的局部变量
                if (arrayPtr.getRegion().isLocal()) {
                    Logging.info("Found local descriptor array, trying to resolve...");
                    resolveLocalDescriptorArray(arrayPtr, size, absEnv);
                } else {
                    Logging.warn("Descriptor array is neither global nor local: " + arrayPtr.getRegion().getClass().getSimpleName());
                }
                continue;
            }
            
            // 全局descriptor数组的情况
            long arrayAddr = arrayPtr.getValue();
            Logging.info("Found global descriptor array at: 0x" + Long.toHexString(arrayAddr));
            directlyResolveNAPIDescriptorsAt(arrayAddr, size);
        }
    }

    /**
     * 解析栈上构造的descriptor数组
     */
    private void resolveLocalDescriptorArray(AbsVal arrayPtr, int size, AbsEnv absEnv) {
        // 对于栈上的descriptor，我们需要通过抽象环境来获取其内容
        RegionBase region = arrayPtr.getRegion();
        long baseOffset = arrayPtr.getValue();
        int ptrSize = MyGlobalState.defaultPointerSize;
        int structSize = ptrSize * 8; // napi_property_descriptor结构体大小
        
        Logging.info("Resolving local descriptor array, base offset: " + baseOffset + ", size: " + size);
        
        for (int i = 0; i < size; i++) {
            long structOffset = baseOffset + i * structSize;
            
            // 尝试解析每个descriptor结构体的字段
            String utf8name = resolveLocalDescriptorField(region, structOffset + ptrSize * 0, absEnv); // utf8name
            Long methodPtr = resolveLocalDescriptorMethodPtr(region, structOffset + ptrSize * 2, absEnv); // method
            
            if (utf8name != null && methodPtr != null) {
                Logging.info("Found local descriptor: " + utf8name + " at 0x" + Long.toHexString(methodPtr));
                MyGlobalState.dynRegNAPIList.add(new NAPIDescriptor(utf8name, GlobalState.flatAPI.toAddr(methodPtr)));
            } else {
                Logging.warn("Failed to resolve local descriptor at offset: " + structOffset);
            }
        }
    }

    /**
     * 从局部变量区域解析字符串字段
     */
    private String resolveLocalDescriptorField(RegionBase region, long fieldOffset, AbsEnv absEnv) {
        ALoc fieldLoc = ALoc.getALoc(region, fieldOffset, MyGlobalState.defaultPointerSize);
        KSet fieldKSet = absEnv.get(fieldLoc);
        
        if (fieldKSet == null || !fieldKSet.isNormal() || fieldKSet.isBot()) {
            return null;
        }
        
        for (AbsVal fieldVal : fieldKSet) {
            if (fieldVal.getRegion().isGlobal()) {
                return getStrFromAddr(fieldVal.getValue());
            }
        }
        return null;
    }

    /**
     * 从局部变量区域解析方法指针字段
     */
    private Long resolveLocalDescriptorMethodPtr(RegionBase region, long fieldOffset, AbsEnv absEnv) {
        ALoc fieldLoc = ALoc.getALoc(region, fieldOffset, MyGlobalState.defaultPointerSize);
        KSet fieldKSet = absEnv.get(fieldLoc);
        
        if (fieldKSet == null || !fieldKSet.isNormal() || fieldKSet.isBot()) {
            return null;
        }
        
        for (AbsVal fieldVal : fieldKSet) {
            if (fieldVal.getRegion().isGlobal()) {
                return fieldVal.getValue();
            }
        }
        return null;
    }

    private void directlyResolveNAPIDescriptorsAt(long ptr, int size){
        boolean failed = false;
        int index = 0;
        int ptrSize = MyGlobalState.defaultPointerSize;

        int structSize = ptrSize*8;
        while(!failed && index < size) {
            Address base = GlobalState.flatAPI.toAddr(ptr + index * structSize);
            Address utf8nameAddr = base.add(ptrSize * 0);
            Address napi_value_nameAddr = base.add(ptrSize * 1);
            Address napi_callbback_methodAddr = base.add(ptrSize * 2);
            Address napi_callbback_getterAddr = base.add(ptrSize * 3);
            Address napi_callbback_setterAddr = base.add(ptrSize * 4);
            Address napi_value_valueAddr = base.add(ptrSize * 5);
            Address attributesAddr = base.add(ptrSize * 6);
            Address dataAddr = base.add(ptrSize * 7);

            String utf8nameStr = null;
            Address napi_callbback_methodTrueAddr = null;
            try {
                Address utf8nameTrueAddr = GlobalState.flatAPI.toAddr(getValueFromAddrWithPtrSize(utf8nameAddr.getOffset(), ptrSize));
                utf8nameStr = getStrFromAddr(utf8nameTrueAddr.getOffset());
            } catch (MemoryAccessException e) {
                throw new RuntimeException(e);
            }

            try {
                napi_callbback_methodTrueAddr = GlobalState.flatAPI.toAddr(getValueFromAddrWithPtrSize(napi_callbback_methodAddr.getOffset(), ptrSize));
            } catch (MemoryAccessException e) {
                throw new RuntimeException(e);
            }

            if(utf8nameStr != null && napi_callbback_methodTrueAddr != null) {
                Logging.info("Find dynamic registered napi: " + utf8nameStr + " at 0x" + Long.toHexString(napi_callbback_methodTrueAddr.getOffset()));
                MyGlobalState.dynRegNAPIList.add(new NAPIDescriptor(utf8nameStr, napi_callbback_methodTrueAddr));
            }else{
                Logging.warn("Failed to resolve NAPI descriptor at 0x"+Long.toHexString(base.getOffset()));
            }

            index++;
        }
    }

    private long getValueFromAddrWithPtrSize(long addr, int ptrSize) throws MemoryAccessException {
        Memory memory = GlobalState.currentProgram.getMemory();
        if (ptrSize == 4) {
            return memory.getInt(GlobalState.flatAPI.toAddr(addr));
        } else if (ptrSize == 8) {
            return memory.getLong(GlobalState.flatAPI.toAddr(addr));
        } else {
            Logging.error("Unknown ptrSize: " + ptrSize);
            return 0;
        }
    }


    private String decodeStr(AbsEnv env, AbsVal val) {
        if (!val.getRegion().isGlobal()) {
            Logging.warn("Cannot decode non global str ptr.");
            return null;
        }
        long addr = val.getValue();
        if (addr < 0x100) {
            return null;
        }
        byte[] bs = null;
        try {
            bs = getStringFromMemory(GlobalState.flatAPI.toAddr(addr));
        } catch (MemoryAccessException e) {
            Logging.error("JNI char* decode failed! 0x"+Long.toHexString(addr));
            return null;
        }
        if (bs == null) {
            return null;
        }
        String s;
        try {
            Charset csets = StandardCharsets.UTF_8;
            CharsetDecoder cd = csets.newDecoder();
            CharBuffer r = cd.decode(ByteBuffer.wrap(bs));
            s = r.toString();
        } catch (CharacterCodingException e) {
            s = Arrays.toString(bs);
        }
        return s;
    }

    private String getStrFromAddr(long addr) {
        byte[] bs = null;
        try {
            bs = getStringFromMemory(GlobalState.flatAPI.toAddr(addr));
        } catch (MemoryAccessException e) {
            Logging.error("Char* decode failed! 0x"+Long.toHexString(addr));
            return null;
        }
        if (bs == null) {
            return null;
        }
        String s;
        try {
            Charset csets = StandardCharsets.UTF_8;
            CharsetDecoder cd = csets.newDecoder();
            CharBuffer r = cd.decode(ByteBuffer.wrap(bs));
            s = r.toString();
        } catch (CharacterCodingException e) {
            s = Arrays.toString(bs);
        }
        return s;
    }

    public static byte[] getStringFromMemory(Address addr) throws MemoryAccessException {
        MemoryBlock mb = GlobalState.currentProgram.getMemory().getBlock(addr);
        if (mb == null) {
            Logging.error("Cannot decode string at 0x"+addr.toString());
            return null;
        }
        if (mb.isWrite()) {
            Logging.error("Constant str not from readonly section!");
        }
        StringBuilder sb = new StringBuilder();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while(mb.getByte(addr) != 0) {
            out.write(mb.getByte(addr));
            addr = addr.add(1);
        }
        return out.toByteArray();
    }

}
