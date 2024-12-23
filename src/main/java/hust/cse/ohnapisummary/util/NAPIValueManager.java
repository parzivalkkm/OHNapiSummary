package hust.cse.ohnapisummary.util;

import com.bai.env.Context;
import com.bai.env.region.Heap;
import com.bai.util.GlobalState;

import java.util.HashMap;
import java.util.LinkedHashMap;
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








}
