package hust.cse.ohnapisummary.mapping;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonElement;
import ghidra.app.script.GhidraScript;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import hust.cse.ohnapisummary.util.MyGlobalState;

import java.util.ArrayList;
import java.util.Map;

public class NAPIJsonParser {
    FlatProgramAPI flatapi;
    GhidraScript script;
    DataTypeManager manager;

    public NAPIJsonParser(FlatProgramAPI flatapi, GhidraScript script, DataTypeManager manager) {
        this.flatapi = flatapi;
        this.script = script;
        this.manager = manager;
    }

    public ArrayList<Map.Entry<Function, hust.cse.ohnapisummary.ir.Function>> run(JsonObject jsonObject) throws InvalidInputException, DuplicateNameException {
        ArrayList<Map.Entry<Function, hust.cse.ohnapisummary.ir.Function>> ret = new ArrayList<>();



        for (Map.Entry<String, JsonElement> e : jsonObject.entrySet()) {
            //        "add": {
            //        "arkts_name": "add",
            //        "params": [
            //            "number",
            //            "number"
            //        ],
            //        "arkts_return_type": "number"
            //    },
            JsonObject obj = e.getValue().getAsJsonObject();
            String name = obj.get("arkts_name").getAsString();
            String returnType = obj.get("arkts_return_type").getAsString();
            JsonArray params = obj.getAsJsonArray("params");

            hust.cse.ohnapisummary.ir.Function irFunc = new hust.cse.ohnapisummary.ir.Function();
        }

        return ret;
    }
}
