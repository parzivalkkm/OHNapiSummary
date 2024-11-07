package hust.cse.ohnapisummary.util;

import com.bai.env.Context;
import com.bai.util.GlobalState;
import ghidra.program.model.listing.Function;

public class NAPIValue {
    enum NAPIValueType {
        PARAM,
        FUNC_CALL
    };
    NAPIValueType nvt;
    Function api = null;
    public long[] callstring = new long[GlobalState.config.getCallStringK()];
    public long callsite;

    public NAPIValue(Context ctx, Function api, long callsite) {
        this.nvt = NAPIValueType.FUNC_CALL;
        this.api = api;
        if (ctx != null) {
            System.arraycopy(ctx.getCallString(), 0, this.callstring, 0, GlobalState.config.getCallStringK());
        }
        this.callsite = callsite;
    }

    public Function getApi() {
        return api;
    }
}
