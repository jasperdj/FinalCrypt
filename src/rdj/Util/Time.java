package rdj.Util;

import java.util.Calendar;


// Todo: refactor this, util functions should not have a state.
public class Time {
    private static Long now;

    public static long updateNow() { return Calendar.getInstance().getTimeInMillis(); }

    public static long getNow() {
        return getNow(false);
    }

    public static long getNow(boolean updateWhenEmpty) {
        if (now == null) {
            if (updateWhenEmpty) return updateNow();
            else throw new NullPointerException();
        }
        return now;
    }

}
