//
//@author SECURITY PRIDE
//@category Analysis
//@keybinding
//@menupath Analysis.OHNapiSummary
//@toolbar

import com.bai.env.funcs.FunctionModelManager;
import com.bai.util.*;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.stream.JsonReader;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import hust.cse.ohnapisummary.checkers.ModuleInitChecker;
import hust.cse.ohnapisummary.checkers.RegisterChecker;
import hust.cse.ohnapisummary.ir.utils.Type;
import hust.cse.ohnapisummary.ir.value.Param;
import hust.cse.ohnapisummary.mapping.NAPIDescriptor;
import hust.cse.ohnapisummary.mapping.NAPIJsonParser;
import hust.cse.ohnapisummary.util.EnvSetup;
import hust.cse.ohnapisummary.util.MyGlobalState;
import org.apache.commons.lang3.StringUtils;
import ghidra.program.model.symbol.Reference;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;

public class OHNapiSummary extends BinAbsInspector {

    // 时间统计数据结构
    public static class PerformanceStatistics {
        public String analysisTimestamp;
        public String soName;
        public long totalExecutionTimeMs;

        // 主要阶段统计
        public Map<String, PhaseStats> phases = new LinkedHashMap<>();

        // 函数分析统计
        public List<FunctionStats> functionAnalysis = new ArrayList<>();

        // 汇总统计
        public SummaryStats summary = new SummaryStats();

        public PerformanceStatistics() {
            this.analysisTimestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        }
    }

    public static class PhaseStats {
        public String phaseName;
        public long startTimeMs;
        public long endTimeMs;
        public long durationMs;
        public String status; // "SUCCESS", "FAILED", "PARTIAL"
        public String details;

        public PhaseStats(String name) {
            this.phaseName = name;
            this.status = "RUNNING";
        }

        public void start() {
            this.startTimeMs = System.currentTimeMillis();
        }

        public void end(String status, String details) {
            this.endTimeMs = System.currentTimeMillis();
            this.durationMs = this.endTimeMs - this.startTimeMs;
            this.status = status;
            this.details = details;
        }
    }

    public static class FunctionStats {
        public String functionName;
        public String address;
        public long analysisTimeMs;
        public String status;
        public String errorMessage;

        public FunctionStats(String name, String addr) {
            this.functionName = name;
            this.address = addr;
        }
    }

    public static class SummaryStats {
        public int totalFunctionsAnalyzed;
        public int successfulAnalysis;
        public int failedAnalysis;
        public int napiRegistrationsFound;
        public long averageFunctionAnalysisTimeMs;
        public String mostTimeConsumingPhase;
        public long mostTimeConsumingPhaseDurationMs;
    }

    // 性能统计实例
    private PerformanceStatistics performanceStats = new PerformanceStatistics();

    @Override
    public void run() throws Exception {
        long overallStart = System.currentTimeMillis();

        // 初始化性能统计
        String exe_path = getCurrentProgram().getExecutablePath();
        performanceStats.soName = Paths.get(exe_path).getFileName().toString();

        // Phase 1: 环境设置
        PhaseStats setupPhase = new PhaseStats("Environment Setup");
        performanceStats.phases.put("setup", setupPhase);
        setupPhase.start();

        try {
            new EnvSetup(getCurrentProgram(), this, getState(), this).run();

            GlobalState.ghidraScript = this;
            GlobalState.config = new Config();
            GlobalState.currentProgram = getCurrentProgram();
            GlobalState.flatAPI = this;

            MyGlobalState.reset(this);

            if (!Logging.init()) {
                setupPhase.end("FAILED", "Logging initialization failed");
                return;
            }

            setupPhase.end("SUCCESS", "Environment setup completed");
        } catch (Exception e) {
            setupPhase.end("FAILED", "Exception during setup: " + e.getMessage());
            throw e;
        }

        // Phase 2: 注册函数分析
        PhaseStats registerPhase = new PhaseStats("Register Function Analysis");
        performanceStats.phases.put("register", registerPhase);
        registerPhase.start();

        try {
            // TODO: 改为从init段中获取Register函数
            // 寻找调用napi_module_register的注册函数
            List<Reference> references = Utils.getReferences(List.of("napi_module_register"));
            if (references.isEmpty()) {
                registerPhase.end("FAILED", "No napi_module_register found");
                Logging.info("No napi_module_register found.");
                Logging.info("This is not a Node-API module.");
                return;
            }

            boolean registerFound = false;
            for (Reference reference : references) {
                Address toAddress = reference.getToAddress();
                Address fromAddress = reference.getFromAddress();
                Function callee = GlobalState.flatAPI.getFunctionAt(toAddress);
                Function caller = GlobalState.flatAPI.getFunctionContaining(fromAddress);

                if (callee == null || caller == null) {
                    Logging.error("Cannot find function at " + toAddress + " or " + fromAddress);
                    continue;
                }
                Logging.info(fromAddress + ": " + caller.getName() + " -> " + toAddress + ": " + callee.getName());
                run4RegisterFunction(caller);
                registerFound = true;
                break;
            }

            if (registerFound) {
                registerPhase.end("SUCCESS", "Register function analysis completed");
            } else {
                registerPhase.end("FAILED", "No valid register function found");
            }
        } catch (Exception e) {
            registerPhase.end("FAILED", "Exception during register analysis: " + e.getMessage());
        }

        if (MyGlobalState.moduleInitFunc == null) {
            Logging.error("No module init function found.");
            return;
        }

        // Phase 3: 模块初始化函数分析
        PhaseStats moduleInitPhase = new PhaseStats("Module Init Analysis");
        performanceStats.phases.put("moduleInit", moduleInitPhase);
        moduleInitPhase.start();

        try {
            run4ModuleInitFunction(MyGlobalState.moduleInitFunc);
            moduleInitPhase.end("SUCCESS", "Module init analysis completed");
        } catch (Exception e) {
            moduleInitPhase.end("FAILED", "Exception during module init: " + e.getMessage());
        }

        // Phase 4: 获取待分析函数列表
        PhaseStats functionDiscoveryPhase = new PhaseStats("Function Discovery");
        performanceStats.phases.put("functionDiscovery", functionDiscoveryPhase);
        functionDiscoveryPhase.start();

        ArrayList<Map.Entry<Function, hust.cse.ohnapisummary.ir.Function>> functionsToAnalyze;
        try {
            functionsToAnalyze = getFunctionsToAnalyze();
            functionDiscoveryPhase.end("SUCCESS", "Found " + functionsToAnalyze.size() + " functions to analyze");
            Logging.info("Found " + functionsToAnalyze.size() + " functions to analyze.");
        } catch (Exception e) {
            functionDiscoveryPhase.end("FAILED", "Exception during function discovery: " + e.getMessage());
            throw e;
        }

        // Phase 5: 函数分析
        PhaseStats functionsAnalysisPhase = new PhaseStats("Functions Analysis");
        performanceStats.phases.put("functionsAnalysis", functionsAnalysisPhase);
        functionsAnalysisPhase.start();

        int successfulAnalysis = 0;
        int failedAnalysis = 0;
        long totalFunctionTime = 0;

        for(int i=0;i<functionsToAnalyze.size();i++) {
            Map.Entry<Function, hust.cse.ohnapisummary.ir.Function> e = functionsToAnalyze.get(i);
            String functionName = e.getKey().getName();
            String functionAddr = e.getKey().getEntryPoint().toString();

            println("Analyzing " + functionName);

            FunctionStats funcStats = new FunctionStats(functionName, functionAddr);
            long startOne = System.currentTimeMillis();

            try {
                // disable timeout if GUI mode.
                // 分析对应的函数
                run4OneFunction(e.getKey(), e.getValue(), !isRunningHeadless());

                long durationOne = System.currentTimeMillis() - startOne;
                funcStats.analysisTimeMs = durationOne;
                funcStats.status = "SUCCESS";
                totalFunctionTime += durationOne;
                successfulAnalysis++;

                println("Analysis spent "+durationOne+" ms for "+functionName);
            } catch (Exception exc) {
                long durationOne = System.currentTimeMillis() - startOne;
                funcStats.analysisTimeMs = durationOne;
                funcStats.status = "FAILED";
                funcStats.errorMessage = exc.getMessage();
                totalFunctionTime += durationOne;
                failedAnalysis++;

                Logging.error("Failed to analyze: "+functionName+", ("+functionAddr+")");
                Logging.error(exc.getMessage());
            }

            performanceStats.functionAnalysis.add(funcStats);

            if (getMonitor().isCancelled() || Thread.currentThread().isInterrupted()) {
                Logging.warn("Run Cancelled.");
                break;
            }
        }

        functionsAnalysisPhase.end("SUCCESS",
                String.format("Analyzed %d functions: %d successful, %d failed",
                        functionsToAnalyze.size(), successfulAnalysis, failedAnalysis));

        // Phase 6: 导出结果
        PhaseStats exportPhase = new PhaseStats("Export Results");
        performanceStats.phases.put("export", exportPhase);
        exportPhase.start();

        try {
            // 将IR写入到文件中
            MyGlobalState.soName = performanceStats.soName;
            FileWriter writer = new FileWriter(exe_path + ".ir.json");
            MyGlobalState.se.export(writer);
            writer.close();

            exportPhase.end("SUCCESS", "IR exported to " + exe_path + ".ir.json");
        } catch (Exception e) {
            exportPhase.end("FAILED", "Export failed: " + e.getMessage());
        }

        // 计算总时间和统计信息
        long totalDuration = System.currentTimeMillis() - overallStart;
        performanceStats.totalExecutionTimeMs = totalDuration;

        // 填充汇总统计
        performanceStats.summary.totalFunctionsAnalyzed = functionsToAnalyze.size();
        performanceStats.summary.successfulAnalysis = successfulAnalysis;
        performanceStats.summary.failedAnalysis = failedAnalysis;
        performanceStats.summary.napiRegistrationsFound = MyGlobalState.dynRegNAPIList.size();
        performanceStats.summary.averageFunctionAnalysisTimeMs =
                functionsToAnalyze.size() > 0 ? totalFunctionTime / functionsToAnalyze.size() : 0;

        // 找出最耗时的阶段
        String mostTimeConsumingPhase = "";
        long maxPhaseDuration = 0;
        for (Map.Entry<String, PhaseStats> phaseEntry : performanceStats.phases.entrySet()) {
            if (phaseEntry.getValue().durationMs > maxPhaseDuration) {
                maxPhaseDuration = phaseEntry.getValue().durationMs;
                mostTimeConsumingPhase = phaseEntry.getValue().phaseName;
            }
        }
        performanceStats.summary.mostTimeConsumingPhase = mostTimeConsumingPhase;
        performanceStats.summary.mostTimeConsumingPhaseDurationMs = maxPhaseDuration;

        // 导出性能统计
        exportPerformanceStatistics(exe_path);

        println("OHNapiSummary script execution time: " + totalDuration + "ms.");
    }

    /**
     * 导出性能统计到文件
     */
    private void exportPerformanceStatistics(String basePath) {
        try {
            // 导出为JSON格式
            String perfJsonPath = basePath + ".performance.json";
            Gson gson = new Gson();
            FileWriter jsonWriter = new FileWriter(perfJsonPath);
            gson.toJson(performanceStats, jsonWriter);
            jsonWriter.close();

            // 导出为可读的文本报告
            String perfReportPath = basePath + ".performance.txt";
            FileWriter reportWriter = new FileWriter(perfReportPath);

            String separator80 = "================================================================================";
            String separator50 = "--------------------------------------------------";
            
            reportWriter.write(separator80 + "\n");
            reportWriter.write("NAPI Analysis Performance Report\n");
            reportWriter.write(separator80 + "\n");
            reportWriter.write("Generated: " + performanceStats.analysisTimestamp + "\n");
            reportWriter.write("SO File: " + performanceStats.soName + "\n");
            reportWriter.write("Total Execution Time: " + performanceStats.totalExecutionTimeMs + " ms\n");
            reportWriter.write("\n");

            // 阶段统计
            reportWriter.write("PHASE ANALYSIS:\n");
            reportWriter.write(separator50 + "\n");
            for (Map.Entry<String, PhaseStats> entry : performanceStats.phases.entrySet()) {
                PhaseStats phase = entry.getValue();
                reportWriter.write(String.format("%-25s: %6d ms [%s] %s\n",
                        phase.phaseName, phase.durationMs, phase.status,
                        phase.details != null ? phase.details : ""));
            }
            reportWriter.write("\n");

            // 函数分析统计
            reportWriter.write("FUNCTION ANALYSIS:\n");
            reportWriter.write(separator50 + "\n");
            reportWriter.write(String.format("Total Functions: %d\n", performanceStats.summary.totalFunctionsAnalyzed));
            reportWriter.write(String.format("Successful: %d\n", performanceStats.summary.successfulAnalysis));
            reportWriter.write(String.format("Failed: %d\n", performanceStats.summary.failedAnalysis));
            reportWriter.write(String.format("Average Time per Function: %d ms\n", performanceStats.summary.averageFunctionAnalysisTimeMs));
            reportWriter.write(String.format("NAPI Registrations Found: %d\n", performanceStats.summary.napiRegistrationsFound));
            reportWriter.write("\n");

            // 最耗时的阶段
            reportWriter.write("PERFORMANCE INSIGHTS:\n");
            reportWriter.write(separator50 + "\n");
            reportWriter.write(String.format("Most Time-Consuming Phase: %s (%d ms)\n",
                    performanceStats.summary.mostTimeConsumingPhase,
                    performanceStats.summary.mostTimeConsumingPhaseDurationMs));

            // 函数分析详情（只显示前10个最耗时的）
            reportWriter.write("\nTOP 10 TIME-CONSUMING FUNCTIONS:\n");
            reportWriter.write(separator50 + "\n");
            
            // 使用传统的Collections.sort避免lambda表达式的Error Prone问题
            List<FunctionStats> sortedFunctions = new ArrayList<>(performanceStats.functionAnalysis);
            java.util.Collections.sort(sortedFunctions, new java.util.Comparator<FunctionStats>() {
                @Override
                public int compare(FunctionStats a, FunctionStats b) {
                    return Long.compare(b.analysisTimeMs, a.analysisTimeMs);
                }
            });
            
            for (int i = 0; i < Math.min(10, sortedFunctions.size()); i++) {
                FunctionStats func = sortedFunctions.get(i);
                reportWriter.write(String.format("%-30s: %6d ms [%s] %s\n",
                        func.functionName, func.analysisTimeMs, func.status,
                        func.errorMessage != null ? func.errorMessage : ""));
            }

            // 失败的函数分析
            List<FunctionStats> failedFunctions = new ArrayList<>();
            for (FunctionStats func : performanceStats.functionAnalysis) {
                if ("FAILED".equals(func.status)) {
                    failedFunctions.add(func);
                }
            }

            if (failedFunctions.size() > 0) {
                reportWriter.write("\nFAILED FUNCTION ANALYSIS:\n");
                reportWriter.write(separator50 + "\n");
                for (FunctionStats func : failedFunctions) {
                    reportWriter.write(String.format("%-30s: %s\n",
                            func.functionName,
                            func.errorMessage != null ? func.errorMessage : "Unknown error"));
                }
            }

            reportWriter.write("\n" + separator80 + "\n");
            reportWriter.close();

            println("Performance statistics exported to:");
            println("  JSON: " + perfJsonPath);
            println("  Report: " + perfReportPath);

        } catch (Exception e) {
            Logging.error("Failed to export performance statistics: " + e.getMessage());
        }
    }

    private ArrayList<Map.Entry<Function, hust.cse.ohnapisummary.ir.Function>> getFunctionsToAnalyze() throws Exception {

        DataTypeManager manager = EnvSetup.getModuleDataTypeManager(this, "node_api_all");
        ArrayList<Map.Entry<Function, hust.cse.ohnapisummary.ir.Function>> functionsToAnalyze = new ArrayList<>();
        for (NAPIDescriptor desc: MyGlobalState.dynRegNAPIList) {
            Function f = this.getFunctionAt(desc.napi_callbback_method);
            hust.cse.ohnapisummary.ir.Function irFunc = new hust.cse.ohnapisummary.ir.Function();

            if (f != null) {
                irFunc.name = desc.utf8name;
                irFunc.params.add(new Param("a1", new Type(null).setTypeDef("napi_env")));
                irFunc.params.add(new Param("a2", new Type(null).setTypeDef("napi_callback_info")));
                irFunc.returnType = new Type(null).setTypeDef("napi_value");

                if (f.getParameterCount() == 0) {
                    // TODO：为函数f添加参数及返回值（都是napi_env env, napi_callback_info info）
                    Parameter[] paramsToSet = new Parameter[2];
                    paramsToSet[0] = new ParameterImpl("env", manager.getDataType("/node_api_all.h/napi_env"), this.getCurrentProgram(), SourceType.USER_DEFINED);
                    paramsToSet[1] = new ParameterImpl("info", manager.getDataType("/node_api_all.h/napi_callback_info"), this.getCurrentProgram(), SourceType.USER_DEFINED);
                    // TODO：为函数f添加返回值（napi_value）
                    Parameter returnTypeToSet = new ReturnParameterImpl(manager.getDataType("/node_api_all.h/napi_value"), this.getCurrentProgram());
                    // 更新函数
                    f.updateFunction(null, returnTypeToSet, Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.USER_DEFINED, paramsToSet);

                }
                functionsToAnalyze.add(Map.entry(f, irFunc));
            }else{
                Logging.warn("Cannot find function for descriptor: "+desc.utf8name + " at " + desc.napi_callbback_method);
            }
        }
        return functionsToAnalyze;
    }

    private void run4RegisterFunction(Function f) {
        GlobalState.reset();
        MyGlobalState.onStartOne(f, null);
        if (isRunningHeadless()) {
            String allArgString = StringUtils.join(getScriptArgs()).strip();
            GlobalState.config = Config.HeadlessParser.parseConfig(allArgString);
        } else {
            GlobalState.ghidraScript = this;
            GlobalState.config = new Config();
            GlobalState.config.setGUI(true); // TODO change

        }

        GlobalState.config.setEnableZ3(false);

        GlobalState.config.clearCheckers();
        GlobalState.config.setEntryAddress("0x"+Long.toHexString(f.getEntryPoint().getOffset()));

        GlobalState.config.setTimeout(-1);

        FunctionModelManager.initAll();

        if (GlobalState.config.isEnableZ3() && !Utils.checkZ3Installation()) {
            return;
        }

        Logging.info("Preparing the program");
        if (!prepareProgram()) {
            Logging.error("Failed to prepare the program");
            return;
        }

        if (isRunningHeadless()) {
            if (!Utils.registerExternalFunctionsConfig(GlobalState.currentProgram, GlobalState.config)) {
                Logging.error("Failed to registerExternalFunctionsConfig, existing.");
                return;
            }
        } else {
            Utils.loadCustomExternalFunctionFromLabelHistory(GlobalState.currentProgram);
        }
        GlobalState.arch = new Architecture(GlobalState.currentProgram);

        boolean success = analyze();
        if (!success) {
            Logging.error("Failed to analyze the program: no entrypoint.");
            return;
        }

        Logging.info("Running checkers");
        RegisterChecker registerChecker = new RegisterChecker("RegisterChecker", "0.1");
        registerChecker.check();
    }

    private void run4ModuleInitFunction(Function f) throws CancelledException {

        GlobalState.reset();
        MyGlobalState.onStartOne(f, null);
        if (isRunningHeadless()) {
            String allArgString = StringUtils.join(getScriptArgs()).strip();
            GlobalState.config = Config.HeadlessParser.parseConfig(allArgString);
        } else {
            GlobalState.ghidraScript = this;
            GlobalState.config = new Config();
            GlobalState.config.setGUI(true); // TODO change

        }

        GlobalState.config.setEnableZ3(false);

        GlobalState.config.clearCheckers();
        GlobalState.config.setEntryAddress("0x"+Long.toHexString(f.getEntryPoint().getOffset()));

        GlobalState.config.setTimeout(-1);

        FunctionModelManager.initAll();

        if (GlobalState.config.isEnableZ3() && !Utils.checkZ3Installation()) {
            return;
        }

        Logging.info("Preparing the program");
        if (!prepareProgram()) {
            Logging.error("Failed to prepare the program");
            return;
        }

        if (isRunningHeadless()) {
            if (!Utils.registerExternalFunctionsConfig(GlobalState.currentProgram, GlobalState.config)) {
                Logging.error("Failed to registerExternalFunctionsConfig, existing.");
                return;
            }
        } else {
            Utils.loadCustomExternalFunctionFromLabelHistory(GlobalState.currentProgram);
        }
        GlobalState.arch = new Architecture(GlobalState.currentProgram);

        boolean success = analyze();
        if (!success) {
            Logging.error("Failed to analyze the program: no entrypoint.");
            return;
        }

        Logging.info("Running checkers");
        ModuleInitChecker moduleInitChecker = new ModuleInitChecker("ModuleInitChecker", "0.1");
        moduleInitChecker.check();
    }


    private void run4OneFunction(Function f,hust.cse.ohnapisummary.ir.Function irFunc,boolean disableTimeout){

        MyGlobalState.onStartOne(f, irFunc);
        GlobalState.reset();
        if (isRunningHeadless()) {
            String allArgString = StringUtils.join(getScriptArgs()).strip();
            GlobalState.config = Config.HeadlessParser.parseConfig(allArgString);
        } else {
            GlobalState.ghidraScript = this;
            GlobalState.config = new Config();
            GlobalState.config.setGUI(true); // TODO change

        }
        GlobalState.config.setEnableZ3(false);
//        GlobalState.config.setDebug(true);
        GlobalState.config.clearCheckers();
        GlobalState.config.setEntryAddress("0x"+Long.toHexString(f.getEntryPoint().getOffset()));
        if (disableTimeout) {
            GlobalState.config.setTimeout(-1);
        }

        if (!Logging.init()) {
            return;
        }
        FunctionModelManager.initAll();
        if (GlobalState.config.isEnableZ3() && !Utils.checkZ3Installation()) {
            return;
        }
        Logging.info("Preparing the program");
        if (!prepareProgram()) {
            Logging.error("Failed to prepare the program");
            return;
        }
        if (isRunningHeadless()) {
            if (!Utils.registerExternalFunctionsConfig(GlobalState.currentProgram, GlobalState.config)) {
                Logging.error("Failed to registerExternalFunctionsConfig, existing.");
                return;
            }
        } else {
            Utils.loadCustomExternalFunctionFromLabelHistory(GlobalState.currentProgram);
        }
        GlobalState.arch = new Architecture(GlobalState.currentProgram);

        boolean success = analyze();
        if (!success) {
            Logging.error("Failed to analyze the program: no entrypoint.");
            return;
        }

        // 分析完成后要用SummaryExporter输出生成的IR
        MyGlobalState.onFinishOne();

    }


}
