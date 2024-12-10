package hust.cse.ohnapisummary.util;

import com.bai.env.Context;
import com.bai.env.region.Heap;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public class NAPICallManager {

    // 用于记录analyze过程中遇到的napi调用
    public final LinkedHashMap<NAPIValue, Context> callSites = new LinkedHashMap<>();

    // Heap region map
    public final Map<Heap, NAPIValue> heapMap = new HashMap<>();

    public void registerCall(NAPIValue napiValue, Context ctx) {
        callSites.put(napiValue, ctx);
    }



}
