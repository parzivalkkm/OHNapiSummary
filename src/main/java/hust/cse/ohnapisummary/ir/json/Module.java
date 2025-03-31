package hust.cse.ohnapisummary.ir.json;

import java.util.ArrayList;
import java.util.List;
import com.google.gson.annotations.SerializedName;

public class Module {
    @SerializedName("hap_name")
    public String hapName = "@TEST_HAP_NAME";

    @SerializedName("so_name")
    public String soName = "@TEST_SO_NAME";

    @SerializedName("module_name")
    public String moduleName;

    // 记录Module下所有函数信息
    @SerializedName("functions")
    public List<Function> allFunctions = new ArrayList<>();

}
