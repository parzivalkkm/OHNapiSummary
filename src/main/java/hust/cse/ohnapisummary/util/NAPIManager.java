package hust.cse.ohnapisummary.util;

import com.bai.env.Context;
import com.bai.util.GlobalState;
import ghidra.program.model.listing.Function;

import java.util.LinkedHashMap;

public class NAPIManager {

    public final LinkedHashMap<NAPIValue, Context> callSites = new LinkedHashMap<>();

    public void registerCall(NAPIValue napiValue, Context ctx) {
        callSites.put(napiValue, ctx);
    }



}
