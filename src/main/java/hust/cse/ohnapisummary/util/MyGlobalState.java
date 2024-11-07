package hust.cse.ohnapisummary.util;

import com.bai.env.Context;
import ghidra.program.model.listing.Function;
import hust.cse.ohnapisummary.checkers.RegisterChecker;

public class MyGlobalState {
    public static NAPIManager napiManager;



    public static void reset() {
        napiManager = new NAPIManager();
    }
}
