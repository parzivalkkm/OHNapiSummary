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
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import hust.cse.ohnapisummary.checkers.ModuleInitChecker;
import hust.cse.ohnapisummary.util.EnvSetup;
import hust.cse.ohnapisummary.util.MyGlobalState;
import org.apache.commons.lang3.StringUtils;
import ghidra.program.model.symbol.Reference;

import java.io.File;
import java.io.FileReader;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class OHNapiSummary extends BinAbsInspector {

    @Override
    public void run() throws Exception {
        long start = System.currentTimeMillis();

        MyGlobalState.reset(this);
        new EnvSetup(getCurrentProgram(), this, getState(), this).run();

        GlobalState.ghidraScript = this;
        GlobalState.config = new Config();
        GlobalState.currentProgram = getCurrentProgram();
        GlobalState.flatAPI = this;

        if (!Logging.init()) {
            return;
        }

        // 寻找module init函数并解析其进行的动态注册
        List<Reference> references = Utils.getReferences(List.of("napi_define_properties"));
        for (Reference reference : references) {
            Address toAddress = reference.getToAddress();
            Address fromAddress = reference.getFromAddress();
            Function callee = GlobalState.flatAPI.getFunctionAt(toAddress);
            Function caller = GlobalState.flatAPI.getFunctionContaining(fromAddress);
            Parameter[] params = callee.getParameters();

            if (callee == null || caller == null) {
                continue;
            }
            Logging.info(fromAddress + ": " + caller.getName() + " -> " + toAddress + ": " + callee.getName());
            runForModuleInitFunction(caller);
            break;
        }

        // 读取 arkts字节码端 pre analysisi阶段获取的json格式函数信息
        String exe_path = getCurrentProgram().getExecutablePath();
        File binary = new File(exe_path);
        File jp = new File(exe_path + ".funcs.json");
        if (! jp.exists()) {
            exe_path = Paths.get(getProjectRootFolder().getProjectLocator().getLocation(), "..", binary.getName()).toString();
            jp = new File(exe_path + ".funcs.json");
        }
        JsonReader reader = new JsonReader(new FileReader(jp));
        JsonObject arktsFuncInfoJson = new Gson().fromJson(reader, JsonObject.class);

        long duration = System.currentTimeMillis() - start;

        println("OHNapiSummary script execution time: " + duration + "ms.");
    }

    private void runForModuleInitFunction(Function f) throws CancelledException {

        GlobalState.reset();

        if (isRunningHeadless()) {
            String allArgString = StringUtils.join(getScriptArgs()).strip();
            GlobalState.config = Config.HeadlessParser.parseConfig(allArgString);
        } else {
            GlobalState.ghidraScript = this;
            GlobalState.config = new Config();
            GlobalState.config.setGUI(true); // TODO change
            // change config here
            GlobalState.config.setEnableZ3(false);

        }

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


    private List<Function> getRegisterFunctionAddress() throws MemoryAccessException {
        FunctionManager functionManager = currentProgram.getFunctionManager();
        MemoryBlock initArrayBlock = currentProgram.getMemory().getBlock(".init_array");

        if (initArrayBlock == null) {
            println("No .init_array section found.");
            return null;
        }

        Address start = initArrayBlock.getStart();
        Address end = initArrayBlock.getEnd();
        List<Function> candidates = new ArrayList<>();

        println("Identifying functions in .init_array section:");

        for (Address addr = start; addr.compareTo(end) < 0; addr = addr.add(currentProgram.getDefaultPointerSize())) {
            Address funcAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(currentProgram.getMemory().getLong(addr));
            Function func = functionManager.getFunctionAt(funcAddr);
            if (func != null) {
                candidates.add(func);
                println("Found function: " + func.getName() + " at address: " + func.getEntryPoint());
            }
        }

        // 检查函数名是否符合 Register.*Entry，仅保留符合的函数
        candidates.removeIf(func -> !func.getName().matches("Register.*Module"));

        return candidates;
    }


    private void printFunctionInfo(Function f) {
        println("Function name: " + f.getName());
        println("Function address: " + f.getEntryPoint());
        println("Function signature: " + f.getSignature());
        println("Function comment: " + f.getComment());
    }

}
