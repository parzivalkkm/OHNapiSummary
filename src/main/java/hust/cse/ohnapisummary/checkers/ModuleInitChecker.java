package hust.cse.ohnapisummary.checkers;

import com.bai.checkers.CheckerBase;
import com.bai.env.*;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.StringUtils;
import com.bai.util.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import hust.cse.ohnapisummary.mapping.NAPIDescriptor;
import hust.cse.ohnapisummary.util.MyGlobalState;
import hust.cse.ohnapisummary.util.NAPIValue;

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
    private Map<Long, Long> valueToFunctionPointerMap = new HashMap<>();
    // 用于记录函数名和对应的napi_value的映射
    private Map<Long, String> valueToFunctionNameMap = new HashMap<>();

    @Override
    public boolean check() {
        for (Map.Entry<NAPIValue, Context> entry : MyGlobalState.napiManager.callsOrValues.entrySet()) {
            NAPIValue napiValue = entry.getKey();
            Context context = entry.getValue();
            long callSite = napiValue.callsite;
            Function caller = GlobalState.flatAPI.getFunctionContaining(GlobalState.flatAPI.toAddr(callSite));
            Function callee = napiValue.getApi();
            if (callee == null) {
                Logging.error("Cannot find called external function for 0x" + Long.toHexString(callSite));
                continue;
            }

            String calleeName = callee.getName();

            if (calleeName.equals("napi_define_properties")) {
                Logging.info("Checking Module Register Function" + caller.getName());

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

                directlyResolveDyRegFromMemcpyParam(caller, (int) size);

            } else if (calleeName.equals("napi_set_named_property")) {
                // 注册形如：
                // static napi_value Init(napi_env env, napi_value exports) {
                //    napi_value fn = nullptr;
                //    napi_create_function(env, nullptr, 0, CalculateArea, nullptr, &fn);
                //    napi_set_named_property(env, exports, "calculateArea", fn);
                //    return exports;
                //}
                Logging.info("Checking Function" + caller.getName());
                // TODO: 解析napi_set_named_property的第三、四个参数
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
                    }else{
                        Logging.error("name is not global.");
                    }
                }

                // 解析napi_set_named_property的第四个参数，即属性值
                KSet valueKSet = getParamKSet(callee, 3, absEnv);
                long value = 0;
                for (AbsVal absVal : valueKSet) {
                    if (absVal.getRegion().isGlobal()) {
                        value = absVal.getValue();
                    }
                }
                Logging.info("name of property is: " + name);

                if (name != null && value != 0) {
                    valueToFunctionNameMap.put(value, name);
                }


            } else if (calleeName.equals("napi_create_function")) {
                // 注册形如：
                // static napi_value Init(napi_env env, napi_value exports) {
                //    napi_value fn = nullptr;
                //    napi_create_function(env, nullptr, 0, CalculateArea, nullptr, &fn);
                //    napi_set_named_property(env, exports, "calculateArea", fn);
                //    return exports;
                //}
                Logging.info("Checking Function" + caller.getName());

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

                // 解析napi_create_function的第六个参数，即napi_value指针
                KSet valueKSet = getParamKSet(callee, 5, absEnv);
                long value = 0;
                for (AbsVal absVal : valueKSet) {
                    if (absVal.getRegion().isGlobal()) {
                        value = absVal.getValue();
                    }
                }
                Logging.info("napi_value pointer is: " + value);

                if (funcPtr != 0 && value != 0) {
                    valueToFunctionPointerMap.put(value, funcPtr);
                }

            }

            // 处理第二种方式注册的函数
            // 遍历valueToFunctionPointerMap以及valueToFunctionNameMap，将其解析为NAPIDescriptor
            for(Map.Entry<Long, Long> entry1 : valueToFunctionPointerMap.entrySet()){
                long value = entry1.getKey();
                long funcPtr = entry1.getValue();
                if (valueToFunctionNameMap.containsKey(value)) {
                    String name = valueToFunctionNameMap.get(value);
                    Logging.info("Find dynamic registered napi: " + name + " at 0x" + Long.toHexString(funcPtr));
                    MyGlobalState.dynRegNAPIList.add(new NAPIDescriptor(name, GlobalState.flatAPI.toAddr(funcPtr)));
                }
            }


        }
        return false;
    }

    private void directlyResolveDyRegFromMemcpyParam(Function function,int size) {
        List<Reference> references = Utils.getReferences(List.of("memcpy"));
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
                return;
            }
            if (!srcPtrKSet.isSingleton()) {
                Logging.error("srcPtrKSet is not singleton.");
                return;
            }
            AbsVal srcPtr = srcPtrKSet.iterator().next();
            Logging.info("srcPtr: " + srcPtr.getValue());

            directlyResolveNAPIDescriptorsAt(srcPtr.getValue(),size);

        }
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
