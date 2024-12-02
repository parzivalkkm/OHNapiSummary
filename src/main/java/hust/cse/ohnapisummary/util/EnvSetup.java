package hust.cse.ohnapisummary.util;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class EnvSetup {

    GhidraState state;
    Program currentProgram;
    FlatProgramAPI flatAPI;
    GhidraScript script; // for debug println

    public EnvSetup(Program currentProgram, FlatProgramAPI flatAPI, GhidraState state, GhidraScript script) {
        this.currentProgram = currentProgram;
        this.flatAPI = flatAPI;
        this.state = state;
        this.script = script;
    }

    protected Program getCurrentProgram() {
        return currentProgram;
    }

    public Structure getNAPIModuleStructType() throws Exception {
        DataTypeManager archive = getModuleDataTypeManager(flatAPI, "node_api_all");
        DataType raw = archive.getDataType("/node_api_all.h/napi_module");
        return (Structure) raw;
    }

    public Structure getNAPIPropertyDescriptorStructType() throws Exception {
        DataTypeManager archive = getModuleDataTypeManager(flatAPI, "node_api_all");
        DataType raw = archive.getDataType("/node_api_all.h/napi_property_descriptor");
        return (Structure) raw;
    }

    public static DataTypeManager getModuleDataTypeManager(FlatProgramAPI flatAPI, String gdt_name) throws Exception {
        // default to jni_all
        if (gdt_name == null) {
            gdt_name = "node_api_all";
        }

        AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(flatAPI.getCurrentProgram());
        DataTypeManagerService service = aam.getDataTypeManagerService();

        DataTypeManager[] managers = service.getDataTypeManagers();
        for (DataTypeManager m : managers) {
            if (m.getName().equals(gdt_name)) {
                return m;
            }
        }

        File napiArchiveFile = Application.getModuleDataFile("OHNativeSummary", gdt_name+".gdt").getFile(true);
        // Archive jniArchive = service.openArchive(jniArchiveFile.getFile(true), false);
        FileDataTypeManager napiArchive = flatAPI.openDataTypeArchive(napiArchiveFile, true);
        return napiArchive;
    }

    public ExternalLocation createExternalFunctionLocation(DataType dt) throws InvalidInputException {
        String name = dt.getName();
        Namespace ext = getCurrentProgram().getExternalManager().getExternalLibrary(Library.UNKNOWN);
        List<ExternalLocation> l = getCurrentProgram().getExternalManager().getExternalLocations(Library.UNKNOWN, name);
        if (l.size() != 0) {
//			script.println("External function "+name+" already exist");
            return l.get(0);
        }
        // 这里的reuse Existing好像是在extAddr有的时候复用？而我们是null，所以和上面的检查并不重复
        ExternalLocation el = getCurrentProgram().getExternalManager().addExtFunction(ext, name,null, SourceType.ANALYSIS, true);
        // set func signature
        Pointer ptr = (Pointer) dt;
        FunctionDefinition fd = (FunctionDefinition) ptr.getDataType();
        ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                el.getFunction().getEntryPoint(),
                fd,
                SourceType.USER_DEFINED
        );
        cmd.applyTo(getCurrentProgram(), TaskMonitor.DUMMY);
        return el;
    }

    public static Map<String, FunctionDefinition> getFuncDefMap(DataTypeManager dtm, String categoryPath) {
        Map<String, FunctionDefinition> dtmap = new HashMap<>();
        Category c = dtm.getCategory(new CategoryPath(categoryPath));
        for(DataType dt: c.getDataTypes()) {
            if (dt instanceof FunctionDefinition) {
                dtmap.put(dt.getName(), (FunctionDefinition) dt);
            }
        }
        return dtmap;
    }

    public void applyFunctionSig(Function function, FunctionDefinition signature) throws InvalidInputException {
        ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                function.getEntryPoint(),
                signature,
                SourceType.USER_DEFINED
        );
        cmd.applyTo(currentProgram, TaskMonitor.DUMMY);
    }

    private void setSigAndThunkInBlock(MemoryBlock memoryBlock, Map<String, FunctionDefinition> fname2sig) throws InvalidInputException {
        // 遍历处理PLT函数，设置签名，设置thunk target
        Address start = memoryBlock.getStart();
        Address end = memoryBlock.getEnd(); // including
        FunctionIterator iterator = currentProgram.getListing().getFunctions(start, true);
        for (Function f: iterator) {
            if (f.getEntryPoint().getOffset() > end.getOffset()) {
                // out of memoryBlock section
                break;
            }
            // get name from map
            String fname = f.getName();
            if (fname2sig.containsKey(fname)) {
                // ensure function signature is uninitialized
                if (f.getParameterCount() == 0) {
                    script.println("Applying signature to "+fname);
                    script.println("Function: "+ fname2sig.get(fname));

//                    Namespace ext = getCurrentProgram().getExternalManager().getExternalLibrary("<EXTERNAL>");
//                    Address address = f.getEntryPoint();
//                    getCurrentProgram().getExternalManager().addExtFunction(ext, fname2sig.get(fname).getName(),address, SourceType.ANALYSIS, true);
                    applyFunctionSig(f, fname2sig.get(fname));
                }
            }
//            // 对于android_log_print这样的函数直接external是true，不需要再thunk到谁，建模逻辑会直接用过来
//            // set up PLT function thunk targets to our external funciton eg: _JNIEnv::CallObjectMethod
//            // 只要getThunkTarget的isExternal是true就可以。这样那边建模逻辑就会用过来。
//            if (f.getParentNamespace().getName().equals(JNI_NAMESPACE) && Utils.JNISymbols.contains(fname)) {
//                // assert can find
//                Function externalTarget = getCurrentProgram().getListing().getFunctions(Library.UNKNOWN, fname).get(0);
//                f.setThunkedFunction(externalTarget);
//            }
        }
    }


    // setup layout and external functions
    public void run() throws Exception {
        Structure napiModule = getNAPIModuleStructType();
        Namespace ext = getCurrentProgram().getExternalManager().getExternalLibrary("<EXTERNAL>");

        DataTypeManager archive = getModuleDataTypeManager(flatAPI, "node_api_all");
//        // 注册napi_module_register
//        DataType napi_module_register_type = archive.getDataType("/node_api_all.h/napi_module_register");
//        ExternalLocation el = createExternalFunctionLocation(napi_module_register_type);
//
//        // 注册napi_define_properties
//        Address[] as = el.getFunction().getFunctionThunkAddresses();
//        int len = as == null ? 0 : as.length;
//        if (len != 0) {
//            script.println("Thunk func already exist.");
//        } else {
//            script.println("Thunk func not exist.");
//        }
        SymbolTable table = currentProgram.getSymbolTable();
        Map<String, FunctionDefinition> fname2sig = getFuncDefMap(getModuleDataTypeManager(flatAPI, "node_api_all"), "/node_api_all.h/functions");
        script.println("Applying extern function signatures");
        MemoryBlock pltblk = flatAPI.getMemoryBlock(".plt");
        if (pltblk == null) {
            script.println("ERROR: cannot find memory block for plt section.");
        } else {
            setSigAndThunkInBlock(pltblk, fname2sig);
        }
        MemoryBlock blk = flatAPI.getMemoryBlock(MemoryBlock.EXTERNAL_BLOCK_NAME);
        if (blk == null) {
            script.println("ERROR: cannot find memory block for external section.");
        } else {
            setSigAndThunkInBlock(blk, fname2sig);
        }
    }

}
