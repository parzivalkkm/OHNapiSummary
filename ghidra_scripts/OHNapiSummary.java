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

public class OHNapiSummary extends BinAbsInspector {

    @Override
    public void run() throws Exception {
        long start = System.currentTimeMillis();


        new EnvSetup(getCurrentProgram(), this, getState(), this).run();

        GlobalState.ghidraScript = this;
        GlobalState.config = new Config();
        GlobalState.currentProgram = getCurrentProgram();
        GlobalState.flatAPI = this;

        MyGlobalState.reset(this);

        if (!Logging.init()) {
            return;
        }

        // TODO: 改为从init段中获取Register函数
        // 寻找调用napi_module_register的注册函数
        List<Reference> references = Utils.getReferences(List.of("napi_module_register"));
        if (references.isEmpty()) {
            Logging.error("No napi_module_register found.");
            return;
        }
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
            break;
        }

        if (MyGlobalState.moduleInitFunc == null) {
            Logging.error("No module init function found.");
            return;
        }
        run4ModuleInitFunction(MyGlobalState.moduleInitFunc);

        ArrayList<Map.Entry<Function, hust.cse.ohnapisummary.ir.Function>> functionsToAnalyze = getFunctionsToAnalyze();

        for(int i=0;i<functionsToAnalyze.size();i++) {
            Map.Entry<Function, hust.cse.ohnapisummary.ir.Function> e = functionsToAnalyze.get(i);
            println("Analyzing " + e.getKey().getName());
            long startOne = System.currentTimeMillis();
            try {
                // disable timeout if GUI mode.
                // 分析对应的函数
                run4OneFunction(e.getKey(), e.getValue(), !isRunningHeadless());
            } catch (Exception exc) {
                Logging.error("Failed to analyze: "+e.getKey().getName()+", ("+e.getKey().getEntryPoint()+")");
                Logging.error(exc.getMessage());
                continue;
            }

            if (getMonitor().isCancelled() || Thread.currentThread().isInterrupted()) {
                Logging.warn("Run Cancelled.");
                break;
                // if cancelled, not add current func to statistics
            }


            long durationOne = System.currentTimeMillis() - startOne;
            println("Analysis spent "+durationOne+" ms for "+e.getKey().getName());
        }

        // 将IR写入到文件中
        String exe_path = getCurrentProgram().getExecutablePath();
        FileWriter writer = new FileWriter(exe_path + ".ir.json");
        MyGlobalState.se.export(writer);

        long duration = System.currentTimeMillis() - start;

        println("OHNapiSummary script execution time: " + duration + "ms.");
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
