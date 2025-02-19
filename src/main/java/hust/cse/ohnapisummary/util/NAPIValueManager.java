package hust.cse.ohnapisummary.util;

import com.bai.env.*;
import com.bai.env.funcs.externalfuncs.ExternalFunctionBase;
import com.bai.env.region.Heap;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import hust.cse.ohnapisummary.env.MyTaintMap;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class NAPIValueManager {
    // NAPI VALUE可以是一个调用（及其上下文），也可以是一个值

    // 用于记录analyze过程中遇到的napi调用或值
    public final LinkedHashMap<NAPIValue, Context> callsOrValues = new LinkedHashMap<>();
    // 记录taint ID的map
    final Map<Long, NAPIValue> idMap = new HashMap<>();
    final Map<NAPIValue, Long> nvIdMap = new HashMap<>();

    long counter = 0;

    static final long stride = 0x10;

    // ensure highest 4 bit is 0x8, Or real value before return.
    static long mask = 0; // 0x80 00 00 00 [...]
    public static long getMask() {
        if (mask != 0) return mask;
        mask = 0x8L << (GlobalState.currentProgram.getDefaultPointerSize() * 8 - 4);
        return mask;
    }

    public static boolean highestBitsMatch(long value) {
        long mask = 0xFL << (GlobalState.currentProgram.getDefaultPointerSize() * 8 - 4);
        return getMask() == (value & mask);
    }

    private long allocateId() {
        long ret = counter;
        counter += stride;
        return ret | getMask();
    }

    // Heap region map
    public final Map<Heap, NAPIValue> heapMap = new HashMap<>();

    public void registerCall(NAPIValue napiValue, Context ctx) {
        callsOrValues.put(napiValue, ctx);
    }

    public long getOrAllocateId(NAPIValue nv){
        if (nvIdMap.containsKey(nv)){
            return nvIdMap.get(nv);
        }
        long newId = allocateId();
        nvIdMap.put(nv,newId);
        idMap.put(newId,nv);
        return newId;
    }

    public NAPIValue getValue(long id) {
        return idMap.get(id);
    }


    public void setupArgsAndCreateTaint(Function cur, AbsEnv env, Context mainContext) {
        Logging.info("setupArgsAndCreateTaint: "+cur.toString());
        Logging.info("Number of params: "+cur.getParameters().length);
        for (int i=0;i<cur.getParameters().length;i++) {
            Parameter p = cur.getParameters()[i];
            List<ALoc> alocs = ExternalFunctionBase.getParamALocs(cur, i, env);
            if (alocs.size() > 1) {
                Logging.warn("setupArg: multiple ALocs found for param !!!");
            }
            if (alocs.isEmpty()) {
                // TODO 这一句一直报错
                Logging.error("Cannot find ALocs for param!!! " +
                        String.format("(Func %s, Param %s %s)", cur.toString(), p.getDataType().getName(), p.getName()));
            }
            for (ALoc al: alocs) {
                NAPIValue napiValue = new NAPIValue(i);
                KSet val = getKSetForValue(TypeCategory.byName(p.getDataType()), cur.getEntryPoint(), napiValue, al.getLen()*8, cur, mainContext, env);
                if (val != null) {
                    env.set(al, val, false);
                }
            }
        }
    }

    public static KSet getKSetForValue(TypeCategory typeCategory, Address callSite, NAPIValue napiValue, int bits, Function callee, Context context, AbsEnv env){
        long newTaint;
        KSet retKSet;
        switch (typeCategory) {
            // 一些不透明的值
            case IN_TRANSPARENT:
            case NAPI_STATUS:
            case NAPI_ENV:
            case NAPI_CALLBACK_INFO:
            case NAPI_VALUE:
                long val = MyGlobalState.napiManager.getOrAllocateId(napiValue);  // 记录在id MAP之中 key是NAPIValue(区分)
                retKSet = new KSet(bits);
                retKSet = retKSet.insert(new AbsVal(val));
                return retKSet;
            case NUMBER:
                newTaint = MyTaintMap.getTaints(napiValue); // 只有数字类型需要污点
                if (MyTaintMap.isNewTaint(newTaint)) {
                    Logging.info("Allocating taint for "+(callee==null?"Param":callee.getName())+" at "+callSite+" with taint "+newTaint);
                }
                return KSet.getTop(newTaint);
            case BUFFER:
                // TODO: 处理heap
            case UNKNOWN:
        }
        return null;
    }








}
