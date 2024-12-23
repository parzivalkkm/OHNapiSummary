package hust.cse.ohnapisummary.util;

import com.bai.env.Context;
import com.bai.util.GlobalState;
import ghidra.program.model.listing.Function;

import java.util.Arrays;
import java.util.Objects;

public class NAPIValue {
    enum NAPIValueType {
        PARAM,
        FUNC_CALL
    };
    NAPIValueType napiValueType;

    public boolean isParamValue() {
        return napiValueType == NAPIValueType.PARAM;
    }

    public long callsite;

    Function api = null;   // NAPI调用类型（FUNC_CALL）时的属性
    public NAPIValue(Context ctx, Function api, long callsite) { // NAPI调用类型的Constructor
        this.napiValueType = NAPIValueType.FUNC_CALL;
        this.api = api;
        if (ctx != null) {
            System.arraycopy(ctx.getCallString(), 0, this.callstring, 0, GlobalState.config.getCallStringK());
        }
        this.callsite = callsite;
    }

    public Function getApi() {
        if (napiValueType != NAPIValueType.FUNC_CALL) {
            throw new RuntimeException("NAPIValue is not a function call");
        }
        return api;
    }


    int paramIndex = -1;   // 参数类型（PARAM）时的属性



    public static final String PARAM_PREFIX = "Param";
    public long[] callstring = new long[GlobalState.config.getCallStringK()];

    public NAPIValue(int index) { // 参数类型的Constructor
        this.napiValueType = NAPIValueType.PARAM;
        this.paramIndex = index;
    }

    public int getParamIndex() {
        if (napiValueType != NAPIValueType.PARAM) {
            throw new RuntimeException("NAPIValue is not a parameter");
        }
        return paramIndex;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NAPIValue napiValue = (NAPIValue) o;
        return paramIndex == napiValue.paramIndex && callsite == napiValue.callsite && napiValueType == napiValue.napiValueType
            && Objects.equals(api, napiValue.api) && Arrays.equals(callstring, napiValue.callstring);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(napiValueType, api, paramIndex, callsite);
        result = 31 * result + Arrays.hashCode(callstring);
        return result;
    }
}
