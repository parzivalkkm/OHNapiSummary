import com.bai.util.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import org.apache.commons.lang3.StringUtils;

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
//        if (conf.getNoModel()) {
//            println("Warning: disabling function models is only for experiment, and should not be enabled in most cases.");
//            FuncCoverage.isNoModel = true;
//        }
//        // only enable detailed info in noModel mode. (for experiment)
//        Statistics stat = new Statistics(conf.getNoModel());
//        stat.addStatistics(conf.getTimeout(), getCurrentProgram().getFunctionManager());
//        println("Java home: "+System.getProperty("java.home"));
//
//        MyGlobalState.reset(this);
//        // setup external blocks
//        new EnvSetup(getCurrentProgram(), this, getState(), this).run();


        List<Function> registerFunctions = getRegisterFunctionAddress();

        for (Function f : registerFunctions) {
            printFunctionInfo(f);
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
        candidates.removeIf(func -> !func.getName().matches("Register.*Entry"));

        return candidates;
    }

    private void printFunctionInfo(Function f) {
        println("Function name: " + f.getName());
        println("Function address: " + f.getEntryPoint());
        println("Function signature: " + f.getSignature());
        println("Function comment: " + f.getComment());
    }
}
