import com.bai.util.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import hust.cse.ohnapisummary.checkers.ModuleInitChecker;
import hust.cse.ohnapisummary.util.EnvSetup;
import org.apache.commons.lang3.StringUtils;
import ghidra.program.model.symbol.Reference;
import hust.cse.ohnapisummary.checkers.RegisterChecker;
import org.python.antlr.op.Add;

import java.util.ArrayList;
import java.util.List;

public class OHNapiSummary extends BinAbsInspector {


    @Override
    public void run() throws Exception {
        long start = System.currentTimeMillis();
        // parse cmdline once
        Config conf = Config.HeadlessParser.parseConfig(StringUtils.join(getScriptArgs()).strip());
        if (conf.getNoOpt()) {
            println("Warning: disabling CalleeSavedReg optimization and local stack value passing optimization is only for experiment, and should not be enabled in most cases.");
        }
        GlobalState.ghidraScript = this;
        GlobalState.config = new Config();
        GlobalState.currentProgram = getCurrentProgram();
        GlobalState.flatAPI = this;
        if (!Logging.init()) {
            return;
        }
        new EnvSetup(getCurrentProgram(), this, getState(), this).run();

        List<Function> registerFunctions = getRegisterFunctionAddress();

        for (Function f : registerFunctions) {
            printFunctionInfo(f);
            handleRegisterFunction(f);
        }

        long duration = System.currentTimeMillis() - start;

        println("OHNapiSummary script execution time: " + duration + "ms.");
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

    private void handleRegisterFunction(Function f) {
        println("Handling function: " + f.getName());

//        reConfig(f);
//        // 创建 RegisterChecker 实例
//        RegisterChecker registerChecker = new RegisterChecker("RegisterChecker", "0.1");
//        registerChecker.moduleRegisterFunc = f;
//        registerChecker.check();
//
//        Function trueRegisterFunction = registerChecker.trueRegisterFunction;
//        if (trueRegisterFunction != null) {
//            println("True register function found: " + trueRegisterFunction.getName());
//            printFunctionInfo(trueRegisterFunction);
//        } else {
//            println("True register function not found.");
//        }

        reConfig(null);
        ModuleInitChecker moduleInitChecker = new ModuleInitChecker("ModuleInitChecker", "0.1");
        moduleInitChecker.check();

    }

//    private Address getTrueRegisterFunctionAddress(AbsEnv absEnv, Function callee) {
//        String name = callee.getName();
//        if (callee.getParameterCount() < 1) {
//            // Skip the call since Ghidra didn't detect suitable number of arguments
//            Logging.debug("Not enough parameters for \"" + name + "()\" function");
//            return null;
//        }
//        KSet argKSet = getParamKSet(callee, 0, absEnv);
//        if (!argKSet.isNormal()) {
//            Logging.debug("Abnormal KSet");
//            return false;
//        }
//        if (!argKSet.isSingleton()) {
//            return false;
//        }
//        AbsVal argAbsVal = argKSet.iterator().next();
//        // We skip non-global regions and big integer values
//        if (argAbsVal.isBigVal() || !argAbsVal.getRegion().isGlobal()) {
//            return false;
//        }
//    }


    private void printFunctionInfo(Function f) {
        println("Function name: " + f.getName());
        println("Function address: " + f.getEntryPoint());
        println("Function signature: " + f.getSignature());
        println("Function comment: " + f.getComment());
    }

    private void reConfig(Function f) {
        GlobalState.reset();
        GlobalState.config = Config.HeadlessParser.parseConfig(StringUtils.join(getScriptArgs()).strip());

        GlobalState.config.clearCheckers();
//        GlobalState.config.setEntryAddress("0x" + Long.toHexString(f.getEntryPoint().getOffset()));
        GlobalState.config.setTimeout(-1);
    }
}
