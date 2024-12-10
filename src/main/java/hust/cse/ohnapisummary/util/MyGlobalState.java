package hust.cse.ohnapisummary.util;

import ghidra.app.script.GhidraScript;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;
import hust.cse.ohnapisummary.checkers.SummaryExporter;
import hust.cse.ohnapisummary.mapping.NAPIDescriptor;
import hust.cse.ohnapisummary.mapping.NAPIMapping;

import java.util.ArrayList;

public class MyGlobalState {

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

    // 以下的field用于存储一些需要全局记录的信息
    public static Function currentFunction;

    public static NAPICallManager napiManager;

    public static ArrayList<NAPIDescriptor> dynRegNAPIList = new ArrayList<>();

    public static ArrayList<NAPIMapping> napiMappingList = new ArrayList<>();

    public static SummaryExporter se;


    public static void reset(GhidraScript main) {
        flatapi = main;
        defaultPointerSize = main.getCurrentProgram().getDefaultPointerSize();
        napiManager = new NAPICallManager();
        se = new SummaryExporter();
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

    // 在analyze具体的一个函数之前调用
    public static void onStartOne(Function f, hust.cse.ohnapisummary.ir.Function irFunc) {
        currentFunction = f;
        se.onStartFunc(irFunc);
        isTaskTimeout = false;
    }

    // 在analyze具体的一个函数之后调用，启动SummaryExporter输出IP
    public static void onFinishOne() {
        se.check();
        se.onFinishFunc();
    }
}
