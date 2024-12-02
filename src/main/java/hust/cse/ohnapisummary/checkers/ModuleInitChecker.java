package hust.cse.ohnapisummary.checkers;

import com.bai.checkers.CheckerBase;
import com.bai.env.*;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.Utils;
import com.caucho.hessian4.io.LocaleHandle;
import com.sun.jna.platform.win32.WinDef;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import hust.cse.ohnapisummary.util.MyGlobalState;
import hust.cse.ohnapisummary.util.NAPIValue;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.ImmutableTriple;
import org.apache.commons.lang3.tuple.Triple;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.logging.LoggingPermission;

public class ModuleInitChecker extends CheckerBase {
    public ModuleInitChecker(String cwe, String version) {
        super(cwe, version);
    }


    Reference reference = null;


    @Override
    public boolean check() {
        Logging.info("Checking ModuleInitChecker");
        for (Map.Entry<NAPIValue, Context> entry : MyGlobalState.napiManager.callSites.entrySet()) {
            NAPIValue napiValue = entry.getKey();
            Context context = entry.getValue();
            long callsite = napiValue.callsite;
            Function caller = GlobalState.flatAPI.getFunctionContaining(GlobalState.flatAPI.toAddr(callsite));
            Function callee = napiValue.getApi();
            if (callee == null) {
                Logging.error("Cannot find called external function for 0x" + Long.toHexString(callsite));
                continue;
            }


            Parameter[] params = callee.getParameters();

            int paramSize = callee.getParameters().length;
            Logging.info("callee: " + callee);
            Logging.info("callee address: " + callee.getEntryPoint());
            Logging.info("param size: " + paramSize);
            Logging.info("caller context: " + Context.getContext(caller).size());
            Logging.info("callee context: " + Context.getContext(callee).size());

            AbsEnv absEnv = context.getAbsEnvIn().get(GlobalState.flatAPI.toAddr(callsite));
            if (absEnv == null) {
                Logging.error("Cannot find absEnv for 0x" + Long.toHexString(callsite));
                continue;
            }

            Parameter descriptorParam = callee.getParameter(3);
            List<ALoc> alocs = getParamALocs(callee, 3, absEnv);

            for (ALoc aloc: alocs) {
                KSet ks = absEnv.get(aloc);
                Logging.info("ALoc: " + aloc);

                // handle RegisterNatives.
                if (descriptorParam.getDataType().getName().equals("napi_property_descriptor *")) {
                    for (AbsVal val: ks) {
                        if (val.getRegion().isGlobal()) {
                            Logging.info("Global region: " + val);
                        } else {
                            Logging.info("Not global region: " + val);
                        }
                        resolveNAPIRegisterAt(val, absEnv);

                    }

                }
            }


        }
        return false;
    }

    private void resolveNAPIRegisterAt(AbsVal ptr, AbsEnv env) {

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
