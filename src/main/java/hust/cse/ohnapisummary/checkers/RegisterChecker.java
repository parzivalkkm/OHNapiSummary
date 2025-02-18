package hust.cse.ohnapisummary.checkers;

import com.bai.checkers.CheckerBase;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
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
import java.util.Map;


public class RegisterChecker  extends CheckerBase {
    public RegisterChecker(String cwe, String version) {
        super(cwe, version);
    }


    @Override
    public boolean check() {
        for (Map.Entry<NAPIValue, Context> entry : MyGlobalState.napiManager.callsOrValues.entrySet()) {
            if (entry.getKey().isRegisterFunction()) {
                NAPIValue napiValue = entry.getKey();
                Context context = entry.getValue();
                long callSite = napiValue.callSite;
                Function caller = GlobalState.flatAPI.getFunctionContaining(GlobalState.flatAPI.toAddr(callSite));
                Logging.info("Checking Module Register Function " + caller.getName());
                Function callee = napiValue.getApi();
                if (callee == null) {
                    Logging.error("Cannot find called external function for 0x" + Long.toHexString(callSite));
                    continue;
                }

                Parameter[] params = callee.getParameters();
                if (params.length != 1) {
                    Logging.error("Module Register Function should have only one parameter");
                    continue;
                }

                Context tempContext = Context.getContext(caller).iterator().next();

                AbsEnv absEnv = tempContext.getAbsEnvIn().get(GlobalState.flatAPI.toAddr(callSite));
                if (absEnv == null) {
                    Logging.error("Cannot find absEnv for 0x" + Long.toHexString(callSite));
                    continue;
                }

                // 解析函数的第0个参数
                KSet moduleStructKSet = getParamKSet(callee, 0, absEnv);
                if (!moduleStructKSet.isNormal()) {
                    Logging.error("moduleStructKSet is not normal");
                    continue;
                }
                if (!moduleStructKSet.isSingleton()) {
                    Logging.error("moduleStructKSet is not singleton");
                    continue;
                }
                AbsVal moduleStructAbsVal = moduleStructKSet.iterator().next();
                Logging.info("moduleStructPtr: " + moduleStructAbsVal.getValue());

                // 解析moduleStruct
                resolverModuleStruct(moduleStructAbsVal.getValue());
            }
        }




        return false;
    }



    private void resolverModuleStruct(long ptr) {
        Address base = GlobalState.flatAPI.toAddr(ptr);
        int ptrSize = MyGlobalState.defaultPointerSize;
        /*
        static napi_module demoModule = {
            .nm_version = 1,                 // 4 Bytes
            .nm_flags = 0,                   // 4 Bytes
            .nm_filename = nullptr,          // 8 Bytes
            .nm_register_func = Init,
            .nm_modname = "entry",
            .nm_priv = ((void*)0),
            .reserved = { 0 },
        };
         */
        Address initFuncAddr = base.add(ptrSize * 2);
        Address moduleNameStrAddr = base.add(ptrSize * 3);


        Address initFuncTrueAddr = null;
        try {
            long initFuncAddrValue = getValueFromAddrWithPtrSize(initFuncAddr.getOffset(), ptrSize);
            initFuncTrueAddr = GlobalState.flatAPI.toAddr(initFuncAddrValue);
        } catch (MemoryAccessException e) {
            Logging.error("Cannot get initFuncAddrValue");
        }
        Logging.info("Init Function Addr: " + initFuncTrueAddr);
        // 获取Function并保存到MyGlobalState
        Function initFunc = GlobalState.flatAPI.getFunctionAt(initFuncTrueAddr);
        if (initFunc == null) {
            Logging.error("Cannot find initFunc at 0x" + Long.toHexString(initFuncTrueAddr.getOffset()));
        } else {
            Logging.info("Init Function: " + initFunc.getName());
        }
        MyGlobalState.moduleInitFunc = initFunc;

        Address moduleNameStrTrueAddr = null;
        try {
            long moduleNameStrAddrValue = getValueFromAddrWithPtrSize(moduleNameStrAddr.getOffset(), ptrSize);
            moduleNameStrTrueAddr = GlobalState.flatAPI.toAddr(moduleNameStrAddrValue);
        } catch (MemoryAccessException e) {
            Logging.error("Cannot get moduleNameStrAddrValue");
        }
        Logging.info("Module Name Addr: " + moduleNameStrTrueAddr);

        String moduleName = getStrFromAddr(moduleNameStrTrueAddr.getOffset());
        MyGlobalState.moduleName = moduleName;
        Logging.info("Module Name: " + moduleName);


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
