package hust.cse.ohnapisummary.env.funcs.sinks;

import com.bai.env.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import hust.cse.ohnapisummary.env.funcs.NAPIFunctionBase;
import hust.cse.ohnapisummary.util.MyGlobalState;
import hust.cse.ohnapisummary.util.NAPIValue;
import hust.cse.ohnapisummary.util.NAPIValueManager;
import hust.cse.ohnapisummary.util.TypeCategory;

import java.util.List;
import java.util.Set;

public class NapiLogFunction extends NAPIFunctionBase {
    public NapiLogFunction() {
        super(Set.of(
            "OH_LOG_Print"
        ));
    }

    /*
        /**
     * @brief Outputs logs.
     *
     * You can use this function to output logs based on the specified log type, log level, service domain, log tag,
     * and variable parameters determined by the format specifier and privacy identifier in the printf format.
     *
     * @param type Indicates the log type. The type for third-party applications is defined by {@link LOG_APP}.
     * @param level Indicates the log level, which can be <b>LOG_DEBUG</b>, <b>LOG_INFO</b>, <b>LOG_WARN</b>,
     * <b>LOG_ERROR</b>, and <b>LOG_FATAL</b>.
     * @param domain Indicates the service domain of logs. Its value is a hexadecimal integer ranging from 0x0 to 0xFFFF.
     * @param tag Indicates the log tag, which is a string used to identify the class, file, or service behavior.
     * @param fmt Indicates the format string, which is an enhancement of a printf format string and supports the privacy
     * identifier. Specifically, {public} or {private} is added between the % character and the format specifier
     * in each parameter. \n
     * @param ... Indicates a list of parameters. The number and type of parameters must map onto the format specifiers
     * in the format string.
     * @return Returns <b>0</b> or a larger value if the operation is successful; returns a value smaller
     * than <b>0</b> otherwise.
     * @since 8
     *
      int OH_LOG_Print(LogType type, LogLevel level, unsigned int domain, const char *tag, const char *fmt, ...)
       __attribute__((__format__(os_log, 5, 6)));
     */

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {

        NAPIValue callNV = recordCall(context, calleeFunc); // 记录调用的nv
        // 不用处理返回值


    }
}
