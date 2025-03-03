package hust.cse.ohnapisummary.env.funcs.nubers;

import com.bai.env.AbsEnv;
import com.bai.env.Context;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import hust.cse.ohnapisummary.env.funcs.NAPIFunctionBase;
import hust.cse.ohnapisummary.util.NAPIValue;
import java.util.Set;

public class NapiGetValueBigintWordsFunction extends NAPIFunctionBase {
    public NapiGetValueBigintWordsFunction() {
        super(Set.of(
            "napi_get_value_bigint_words"
        ));
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {
        NAPIValue nv = NAPIFunctionBase.recordCall(context, calleeFunc);

        // TODO 对连续内存进行建模？
    }
}
