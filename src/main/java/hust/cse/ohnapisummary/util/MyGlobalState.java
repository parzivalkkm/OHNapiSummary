package hust.cse.ohnapisummary.util;

import com.bai.env.Context;
import ghidra.program.model.listing.Function;
import hust.cse.ohnapisummary.checkers.RegisterChecker;

public class MyGlobalState {
    public enum AnalysisType {
        UNKNOWN,
        MODULE_INIT_FUNC,
        REGISTER_FUNC,
        NORMAL_FUNC
    }

    public static AnalysisType currentAnalysis = AnalysisType.UNKNOWN;

    public static PcodePrettyPrinter pp;

    // 以下属性用于模块初始化函数的分析

    public static RegisterChecker registerChecker;
    public static Function moduleInitFunc;
    public static Context moduleInitFuncContext;
}
