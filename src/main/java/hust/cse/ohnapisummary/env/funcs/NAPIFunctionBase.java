package hust.cse.ohnapisummary.env.funcs;

import com.bai.env.*;
import com.bai.env.funcs.externalfuncs.ExternalFunctionBase;
import com.bai.env.region.Heap;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import hust.cse.ohnapisummary.env.MyTaintMap;
import hust.cse.ohnapisummary.util.MyGlobalState;
import hust.cse.ohnapisummary.util.NAPIValue;
import hust.cse.ohnapisummary.util.NAPIValueManager;
import hust.cse.ohnapisummary.util.TypeCategory;

import java.util.List;
import java.util.Set;

public abstract class NAPIFunctionBase extends ExternalFunctionBase {

    public static Address currentCallSite;

    @Override
    public void defineDefaultSignature(Function callFunction) {
    }

    public NAPIFunctionBase(Set<String> symbols) {
        super(symbols);
    }

    public static NAPIValue recordCall(Context ctx, Function api) {
        NAPIValue nv = new NAPIValue(ctx, api, currentCallSite.getOffset());
        MyGlobalState.napiManager.registerCall(nv, ctx);
        return nv;
    }

    public static NAPIValue recordLocal(Context ctx, Function api, int retIntoParamIndex) {
        NAPIValue nv = new NAPIValue(api, currentCallSite.getOffset(),retIntoParamIndex);
        MyGlobalState.napiManager.registerCall(nv, ctx);
        return nv;
    }

    public static NAPIValue recordLocalMultiRet(Context ctx, Function api, int retIntoParamIndex, int multiRetSIndex) {
        NAPIValue nv = new NAPIValue(api, currentCallSite.getOffset(),retIntoParamIndex,multiRetSIndex);
        MyGlobalState.napiManager.registerCall(nv, ctx);
        return nv;
    }

    public static NAPIValue recordAllocCall(Context context, Function callFunc, Heap heap) {
        NAPIValue napiValue = recordCall(context, callFunc);
        MyGlobalState.napiManager.heapMap.put(heap, napiValue);
        return napiValue;
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {

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

    public static ALoc toALoc(AbsVal val, int size) {
        return ALoc.getALoc(val.getRegion(), val.getValue(), size);
    }



}
