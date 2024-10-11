package hust.cse.ohnapisummary.ir.value;

import hust.cse.ohnapisummary.ir.utils.Constant;
import hust.cse.ohnapisummary.ir.utils.Type;

public class Str extends Constant {
    public String val;
    public static Str of(String s) {
        Str ret = new Str();
        ret.val = s;
        ret.type = Type.CSTR;
        return ret;
    }

    @Override
    public String toValueString() {
        return type.toString()+" \""+val+"\"";
    }
}
