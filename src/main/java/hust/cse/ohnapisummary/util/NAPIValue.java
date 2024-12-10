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
    NAPIValueType nvt;

    public long callsite;

    Function api = null;
    int paramIndex = -1;

    public static final String PARAM_PREFIX = "Param";
    public long[] callstring = new long[GlobalState.config.getCallStringK()];

    public NAPIValue(Context ctx, Function api, long callsite) {
        this.nvt = NAPIValueType.FUNC_CALL;
        this.api = api;
        if (ctx != null) {
            System.arraycopy(ctx.getCallString(), 0, this.callstring, 0, GlobalState.config.getCallStringK());
        }
        this.callsite = callsite;
    }

    public boolean isParamValue() {
        return nvt == NAPIValueType.PARAM;
    }

    public Function getApi() {
        if (nvt != NAPIValueType.FUNC_CALL) {
            throw new RuntimeException("NAPIValue is not a function call");
        }
        return api;
    }

    public int getParamIndex() {
        if (nvt != NAPIValueType.PARAM) {
            throw new RuntimeException("NAPIValue is not a parameter");
        }
        return paramIndex;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NAPIValue napiValue = (NAPIValue) o;
        return paramIndex == napiValue.paramIndex && callsite == napiValue.callsite && nvt == napiValue.nvt
            && Objects.equals(api, napiValue.api) && Arrays.equals(callstring, napiValue.callstring);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(nvt, api, paramIndex, callsite);
        result = 31 * result + Arrays.hashCode(callstring);
        return result;
    }
}
