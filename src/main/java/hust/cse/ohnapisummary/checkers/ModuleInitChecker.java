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
import java.util.List;
import java.util.Map;

public class ModuleInitChecker extends CheckerBase {
    public ModuleInitChecker(String cwe, String version) {
        super(cwe, version);
    }


    Reference reference = null;


    @Override
    public boolean check() {
        for (Map.Entry<NAPIValue, Context> entry : MyGlobalState.napiManager.callSites.entrySet()) {
            NAPIValue napiValue = entry.getKey();
            Context context = entry.getValue();
            long callSite = napiValue.callsite;
            Function caller = GlobalState.flatAPI.getFunctionContaining(GlobalState.flatAPI.toAddr(callSite));
            Logging.info("Checking ModuleInit Function" + caller.getName());
            Function callee = napiValue.getApi();
            if (callee == null) {
                Logging.error("Cannot find called external function for 0x" + Long.toHexString(callSite));
                continue;
            }

            Parameter[] params = callee.getParameters();

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

            // 解析napi_define_properties的第四个参数,即napi_property_descriptor数组的指针，因为是local最终以失败告终
//            Parameter descriptorParam = callee.getParameter(3);
//            KSet descriptorKSet =  getParamKSet(callee, 3, absEnv);

            // handle RegisterNatives.
//            if (descriptorParam.getDataType().getName().equals("napi_property_descriptor *")) {
//                for (AbsVal val: descriptorKSet) {
//                    if (val.getRegion().isGlobal()) {
//                        Logging.info("Global region: " + val);
//                    } else {
//                        Logging.info("Not global region: " + val);
//                    }
//                    printALocBits(val, absEnv, (int) (size * 8));
//                    resolveNAPIDescriptorAt(val, absEnv);
//
//                }
//
//            }


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

    private void printALocBits(AbsVal ptr, AbsEnv env,int size) {
        ALoc ptrALoc = ALoc.getALoc(ptr.getRegion(), ptr.getValue(), 1);
        if (ptrALoc.isGlobalReadable()) {
            String str = StringUtils.getStringFromProgramData(GlobalState.flatAPI.toAddr(ptr.getValue()));
            if (str == null) {
                Logging.error("Failed to get string from 0x"+Long.toHexString(ptr.getValue()));
                return;
            }
            byte[] tmp = str.getBytes();
            byte[] bytes = new byte[Math.min(str.length(), size) + 1];
            // 将bytes转化为16进制字符串然后输出
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = tmp[i];
            }
            String hex = "";
            for (byte b : bytes) {
                hex += String.format("%02X", b);
            }
            Logging.info("0x"+Long.toHexString(ptr.getValue()) + " : " + hex);

        }else{
            Logging.error("Cannot read from 0x"+Long.toHexString(ptr.getValue()));
        }
    }


    private void resolveNAPIDescriptorAt(AbsVal ptr, AbsEnv env) {
        boolean failed = false;
        int index = 0;
        int ptrSize = MyGlobalState.defaultPointerSize;

        int structSize = ptrSize*8;
        while(!failed) {
            long base = ptr.getValue() + index * structSize;
            Logging.info("Resolving NAPI descriptor at 0x"+Long.toHexString(base));
            ALoc utf8name = ALoc.getALoc(ptr.getRegion(), base + ptrSize*0, ptrSize);
            ALoc napi_value_name = ALoc.getALoc(ptr.getRegion(), base + ptrSize*1, ptrSize);
            ALoc napi_callbback_method = ALoc.getALoc(ptr.getRegion(), base + ptrSize*2, ptrSize);
            ALoc napi_callbback_getter = ALoc.getALoc(ptr.getRegion(), base + ptrSize*3, ptrSize);
            ALoc napi_callbback_setter = ALoc.getALoc(ptr.getRegion(), base + ptrSize*4, ptrSize);
            ALoc napi_value_value = ALoc.getALoc(ptr.getRegion(), base + ptrSize*5, ptrSize);
            ALoc attributes = ALoc.getALoc(ptr.getRegion(), base + ptrSize*6, ptrSize);
            ALoc data = ALoc.getALoc(ptr.getRegion(), base + ptrSize*7, ptrSize);

            KSet utf8nameKSet = env.get(utf8name);
            KSet napi_callbback_methodKSet = env.get(napi_callbback_method);
            if (utf8nameKSet.isTop()) {
                failed = true;
                Logging.error("Failed to resolve NAPI descriptor at 0x"+Long.toHexString(base) + " because of utf8name(" + Long.toHexString(base) + ") KSet is top.");
                break;
            }
            if (napi_callbback_methodKSet.isTop()) {
                failed = true;
                Logging.error("Failed to resolve NAPI descriptor at 0x"+Long.toHexString(base) + " because of napi_callbback_method(" + Long.toHexString(base + ptrSize*2) + ") KSet is top.");
                break;
            }
            if (napi_callbback_methodKSet.getInnerSet().size() != 1) {
                failed = true;
                Logging.error("Failed to resolve NAPI descriptor at 0x"+Long.toHexString(base) + " because of napi_callbback_method(" + Long.toHexString(base + ptrSize*2) + ") KSet size is not 1 but " + napi_callbback_methodKSet.getInnerSet().size());
//                break;
            }

            AbsVal utf8nameVal = utf8nameKSet.iterator().next();
            String utf8nameStr = decodeStr(env, utf8nameVal);
            Logging.info("utf8name: " + utf8nameStr);

//            AbsVal func_addr = napi_callbback_methodKSet.iterator().next();
//            Logging.info("func_addr: " + func_addr);
            index++;
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

    public static byte[] getStringFromMemory(Address addr) throws MemoryAccessException {
        MemoryBlock mb = GlobalState.currentProgram.getMemory().getBlock(addr);
        if (mb == null) {
            Logging.error("JNI cannot decode string at 0x"+addr.toString());
            return null;
        }
        if (mb.isWrite()) {
            Logging.error("JNI constant str not from readonly section!");
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
