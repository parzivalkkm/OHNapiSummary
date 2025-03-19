package hust.cse.ohnapisummary.util;

import com.bai.env.*;
import com.bai.env.funcs.externalfuncs.ExternalFunctionBase;
import com.bai.util.Logging;
import ghidra.app.script.GhidraScript;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.util.task.TaskMonitor;
import hust.cse.ohnapisummary.checkers.SummaryExporter;
import hust.cse.ohnapisummary.env.MyTaintMap;
import hust.cse.ohnapisummary.mapping.NAPIDescriptor;
import org.python.antlr.op.Add;

import java.util.ArrayList;
import java.util.List;

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
    // 当前在分析的函数
    public static Function currentFunction;

    // 管理NPAI调用、污点值的记录
    public static NAPIValueManager napiManager;

    // 动态注册的本地函数的描述符
    public static ArrayList<NAPIDescriptor> dynRegNAPIList = new ArrayList<>();

    // 生成摘要的checker的实例
    public static SummaryExporter se;

    // 以下记录Module的信息
    // 记录当前module的名字
    public static String moduleName;
    // 记录当前module的init函数
    public static Function moduleInitFunc;


    public static void reset(GhidraScript main) {
        flatapi = main;
        defaultPointerSize = main.getCurrentProgram().getDefaultPointerSize();
        napiManager = new NAPIValueManager();
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
        napiManager = new NAPIValueManager(); // TODO: 这里要不要继承前一个的性质？
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
