package hust.cse.ohnapisummary.env.funcs.nubers;

import com.bai.env.AbsEnv;
import com.bai.env.Context;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import hust.cse.ohnapisummary.env.funcs.NAPIFunctionBase;
import hust.cse.ohnapisummary.util.NAPIValue;
import java.util.Set;

public class NapiCreateBigintWordsFunction  extends NAPIFunctionBase {
    public NapiCreateBigintWordsFunction() {
        super(Set.of(
            "napi_create_bigint_words"
        ));
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {

        //NAPI_EXTERN napi_status napi_create_bigint_words(napi_env env,
        //                                                 int sign_bit,
        //                                                 size_t word_count,
        //                                                 const uint64_t* words,
        //                                                 napi_value* result);

        NAPIValue nv = NAPIFunctionBase.recordCall(context, calleeFunc);

        // TODO 要对heap进行建模？
    }
}
