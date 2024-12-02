package hust.cse.ohnapisummary.util;

import com.bai.env.Context;
import ghidra.app.script.GhidraScript;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;
import hust.cse.ohnapisummary.checkers.RegisterChecker;

public class MyGlobalState {
    public static NAPIManager napiManager;

    public static FlatProgramAPI flatapi;

    public static int defaultPointerSize;

    // global decompiler result cache
    public static DecompilerCache decom;
    public static PcodePrettyPrinter pp;
    public static TaskMonitor monitor;

    // if current solver timed out.
    // init: before each run, init to false
    // if timeout, set at Context.mainLoopTimeout
    // check at context main loop for timeout.
    public static boolean isTaskTimeout = false;


    public static void reset(GhidraScript main) {
        flatapi = main;
        napiManager = new NAPIManager();
        try {
            decom = new DecompilerCache(main.getState());
        } catch (RuntimeException e) {
            main.println(e.getMessage());
            e.printStackTrace();
        }
        pp = new PcodePrettyPrinter(main.getCurrentProgram());
        monitor = main.getMonitor();
        isTaskTimeout = false;
    }

}
