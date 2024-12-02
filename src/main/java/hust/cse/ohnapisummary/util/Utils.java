package hust.cse.ohnapisummary.util;


import ghidra.program.model.listing.Function;


public class Utils {



    public static String funcNameAndAddr(Function func) {
        return String.format(
                "%s @ %s",
                getFuncName(func),
                func.getEntryPoint().toString());
    }

    public static String getFuncName(Function func) {
        if (func.getName() != null)
            return func.getName();
        return "(undefined)";
    }



}
