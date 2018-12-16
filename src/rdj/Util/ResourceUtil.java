package rdj.Util;

import rdj.GUIFX;

import java.io.InputStream;
import java.net.URL;

public class ResourceUtil {
    public static URL getResource(String name) { return GUIFX.class.getResource(name); }

    public static InputStream getResourceAsStream(String name) { return GUIFX.class.getResourceAsStream(name); }

    // Todo: getClassName is very confusing, find a better alternative for its functionality/purpose.
    public static String getClassName(){ return GUIFX.class.getName(); }
}
