package hust.cse.ohnapisummary.util;

import com.bai.env.Context;

import java.util.LinkedHashMap;

public class NAPICallManager {

    public final LinkedHashMap<NAPIValue, Context> callSites = new LinkedHashMap<>();

    public void registerCall(NAPIValue napiValue, Context ctx) {
        callSites.put(napiValue, ctx);
    }



}
