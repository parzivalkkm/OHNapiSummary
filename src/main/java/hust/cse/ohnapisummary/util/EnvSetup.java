package hust.cse.ohnapisummary.util;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.Application;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

import java.io.File;

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
        DataTypeManager archive = getModuleDataTypeManager(flatAPI, "node_api_basic");
        DataType raw = archive.getDataType("/node_api_basic.h/napi_module");
        return (Structure) raw;
    }

    public Structure getNAPIPropertyDescriptorStructType() throws Exception {
        DataTypeManager archive = getModuleDataTypeManager(flatAPI, "node_api_basic");
        DataType raw = archive.getDataType("/node_api_basic.h/napi_property_descriptor");
        return (Structure) raw;
    }

    public static DataTypeManager getModuleDataTypeManager(FlatProgramAPI flatAPI, String gdt_name) throws Exception {
        // default to jni_all
        if (gdt_name == null) {
            gdt_name = "node_api_basic";
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



    // setup layout and external functions
    public void run() throws Exception {
        Structure napiModule = getNAPIModuleStructType();

    }
}
