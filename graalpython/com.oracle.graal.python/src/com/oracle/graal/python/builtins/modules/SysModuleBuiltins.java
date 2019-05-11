/*
 * Copyright (c) 2017, 2019, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * The Universal Permissive License (UPL), Version 1.0
 *
 * Subject to the condition set forth below, permission is hereby granted to any
 * person obtaining a copy of this software, associated documentation and/or
 * data (collectively the "Software"), free of charge and under any and all
 * copyright rights in the Software, and any and all patent rights owned or
 * freely licensable by each licensor hereunder covering either (i) the
 * unmodified Software as contributed to or provided by such licensor, or (ii)
 * the Larger Works (as defined below), to deal in both
 *
 * (a) the Software, and
 *
 * (b) any piece of software and/or hardware listed in the lrgrwrks.txt file if
 * one is included with the Software each a "Larger Work" to which the Software
 * is contributed by such licensors),
 *
 * without restriction, including without limitation the rights to copy, create
 * derivative works of, display, perform, and distribute the Software and make,
 * use, sell, offer for sale, import, export, have made, and have sold the
 * Software and the Larger Work(s), and to sublicense the foregoing rights on
 * either these or other terms.
 *
 * This license is subject to the following condition:
 *
 * The above copyright notice and either this complete permission notice or at a
 * minimum a reference to the UPL must be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.oracle.graal.python.builtins.modules;

import static com.oracle.graal.python.builtins.PythonBuiltinClassType.TypeError;
import static com.oracle.graal.python.builtins.PythonBuiltinClassType.ValueError;
import static com.oracle.graal.python.nodes.SpecialMethodNames.__SIZEOF__;

import java.io.IOException;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import com.oracle.graal.python.PythonLanguage;
import com.oracle.graal.python.builtins.Builtin;
import com.oracle.graal.python.builtins.CoreFunctions;
import com.oracle.graal.python.builtins.PythonBuiltins;
import com.oracle.graal.python.builtins.modules.SysModuleBuiltinsFactory.GetFrameNodeFactory;
import com.oracle.graal.python.builtins.objects.PNone;
import com.oracle.graal.python.builtins.objects.exception.PBaseException;
import com.oracle.graal.python.builtins.objects.ints.PInt;
import com.oracle.graal.python.builtins.objects.list.PList;
import com.oracle.graal.python.builtins.objects.module.PythonModule;
import com.oracle.graal.python.builtins.objects.str.PString;
import com.oracle.graal.python.nodes.PRaiseNode;
import com.oracle.graal.python.nodes.call.special.LookupAndCallUnaryNode;
import com.oracle.graal.python.nodes.call.special.LookupAndCallUnaryNode.NoAttributeHandler;
import com.oracle.graal.python.nodes.function.PythonBuiltinBaseNode;
import com.oracle.graal.python.nodes.function.PythonBuiltinNode;
import com.oracle.graal.python.nodes.function.builtins.PythonBinaryBuiltinNode;
import com.oracle.graal.python.nodes.function.builtins.PythonUnaryBuiltinNode;
import com.oracle.graal.python.nodes.object.GetClassNode;
import com.oracle.graal.python.nodes.util.CastToIntegerFromIntNode;
import com.oracle.graal.python.nodes.util.ExceptionStateNodes.GetCaughtExceptionNode;
import com.oracle.graal.python.runtime.PythonContext;
import com.oracle.graal.python.runtime.PythonCore;
import com.oracle.graal.python.runtime.PythonOptions;
import com.oracle.graal.python.runtime.exception.PException;
import com.oracle.graal.python.runtime.exception.PythonErrorType;
import com.oracle.truffle.api.CompilerDirectives;
import com.oracle.truffle.api.CompilerDirectives.TruffleBoundary;
import com.oracle.truffle.api.Truffle;
import com.oracle.truffle.api.TruffleFile;
import com.oracle.truffle.api.TruffleLanguage.Env;
import com.oracle.truffle.api.TruffleOptions;
import com.oracle.truffle.api.dsl.Cached;
import com.oracle.truffle.api.dsl.Cached.Shared;
import com.oracle.truffle.api.dsl.CachedLanguage;
import com.oracle.truffle.api.dsl.GenerateNodeFactory;
import com.oracle.truffle.api.dsl.NodeFactory;
import com.oracle.truffle.api.dsl.Specialization;
import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.DirectCallNode;
import com.oracle.truffle.api.nodes.RootNode;

@CoreFunctions(defineModule = "sys")
public class SysModuleBuiltins extends PythonBuiltins {
    private static final String LICENSE = "Copyright (c) Oracle and/or its affiliates. Licensed under the Universal Permissive License v 1.0 as shown at http://oss.oracle.com/licenses/upl.";
    private static final String COMPILE_TIME;
    static {
        String compile_time;
        try {
            compile_time = new Date(PythonBuiltins.class.getResource("PythonBuiltins.class").openConnection().getLastModified()).toString();
        } catch (IOException e) {
            compile_time = "";
        }
        COMPILE_TIME = compile_time;
    }

    private static final String[] SYS_PREFIX_ATTRIBUTES = new String[]{"prefix", "exec_prefix"};
    private static final String[] BASE_PREFIX_ATTRIBUTES = new String[]{"base_prefix", "base_exec_prefix"};

    @Override
    protected List<? extends NodeFactory<? extends PythonBuiltinBaseNode>> getNodeFactories() {
        return SysModuleBuiltinsFactory.getFactories();
    }

    @Override
    public void initialize(PythonCore core) {
        builtinConstants.put("abiflags", "");
        builtinConstants.put("byteorder", ByteOrder.nativeOrder() == ByteOrder.LITTLE_ENDIAN ? "little" : "big");
        builtinConstants.put("copyright", LICENSE);
        builtinConstants.put("dont_write_bytecode", true);
        builtinConstants.put("modules", core.factory().createDict());
        builtinConstants.put("path", core.factory().createList());
        builtinConstants.put("builtin_module_names", core.factory().createTuple(core.builtinModuleNames()));
        builtinConstants.put("maxsize", Integer.MAX_VALUE);
        builtinConstants.put("version_info", core.factory().createTuple(new Object[]{PythonLanguage.MAJOR, PythonLanguage.MINOR, PythonLanguage.MICRO, "dev", 0}));
        builtinConstants.put("version", PythonLanguage.VERSION +
                        " (" + COMPILE_TIME + ")" +
                        "\n[" + Truffle.getRuntime().getName() + ", Java " + System.getProperty("java.version") + "]");
        builtinConstants.put("graal_python_is_native", TruffleOptions.AOT);
        // the default values taken from JPython
        builtinConstants.put("float_info", core.factory().createTuple(new Object[]{
                        Double.MAX_VALUE,       // DBL_MAX
                        Double.MAX_EXPONENT,    // DBL_MAX_EXP
                        308,                    // DBL_MIN_10_EXP
                        Double.MIN_VALUE,       // DBL_MIN
                        Double.MIN_EXPONENT,    // DBL_MIN_EXP
                        -307,                   // DBL_MIN_10_EXP
                        10,                     // DBL_DIG
                        53,                     // DBL_MANT_DIG
                        2.2204460492503131e-16, // DBL_EPSILON
                        2,                      // FLT_RADIX
                        1                       // FLT_ROUNDS
        }));
        builtinConstants.put("maxunicode", Character.MAX_CODE_POINT);

        String os = getPythonOSName();
        builtinConstants.put("platform", os);
        if (os.equals("darwin")) {
            builtinConstants.put("_framework", PNone.NONE);
        }
        builtinConstants.put("__gmultiarch", getPythonArch() + "-" + os);

        super.initialize(core);

        // we need these during core initialization, they are re-set in postInitialize
        postInitialize(core);
    }

    @Override
    public void postInitialize(PythonCore core) {
        super.postInitialize(core);
        PythonModule sys = core.lookupBuiltinModule("sys");
        PythonContext context = core.getContext();
        String[] args = context.getEnv().getApplicationArguments();
        sys.setAttribute("argv", core.factory().createList(Arrays.copyOf(args, args.length, Object[].class)));

        String prefix = PythonCore.getSysPrefix(context.getEnv());
        for (String name : SysModuleBuiltins.SYS_PREFIX_ATTRIBUTES) {
            sys.setAttribute(name, prefix);
        }

        String base_prefix = PythonCore.getSysBasePrefix(context.getEnv());
        for (String name : SysModuleBuiltins.BASE_PREFIX_ATTRIBUTES) {
            sys.setAttribute(name, base_prefix);
        }

        sys.setAttribute("executable", PythonOptions.getOption(context, PythonOptions.Executable));
        sys.setAttribute("graal_python_home", context.getLanguage().getHome());
        sys.setAttribute("graal_python_core_home", PythonOptions.getOption(context, PythonOptions.CoreHome));
        sys.setAttribute("graal_python_stdlib_home", PythonOptions.getOption(context, PythonOptions.StdLibHome));
        sys.setAttribute("__flags__", core.factory().createTuple(new Object[]{
                        false, // bytes_warning
                        !PythonOptions.getFlag(context, PythonOptions.PythonOptimizeFlag), // debug
                        true,  // dont_write_bytecode
                        false, // hash_randomization
                        PythonOptions.getFlag(context, PythonOptions.IgnoreEnvironmentFlag), // ignore_environment
                        PythonOptions.getFlag(context, PythonOptions.InspectFlag), // inspect
                        PythonOptions.getFlag(context, PythonOptions.TerminalIsInteractive), // interactive
                        PythonOptions.getFlag(context, PythonOptions.IsolateFlag), // isolated
                        PythonOptions.getFlag(context, PythonOptions.NoSiteFlag), // no_site
                        PythonOptions.getFlag(context, PythonOptions.NoUserSiteFlag), // no_user_site
                        PythonOptions.getFlag(context, PythonOptions.PythonOptimizeFlag), // optimize
                        PythonOptions.getFlag(context, PythonOptions.QuietFlag), // quiet
                        PythonOptions.getFlag(context, PythonOptions.VerboseFlag), // verbose
                        false, // dev_mode
                        0, // utf8_mode
        }));

        Env env = context.getEnv();
        String option = PythonOptions.getOption(context, PythonOptions.PythonPath);
        Object[] path;
        int pathIdx = 0;
        boolean doIsolate = PythonOptions.getOption(context, PythonOptions.IsolateFlag);
        int defaultPaths = doIsolate ? 2 : 3;
        if (option.length() > 0) {
            String[] split = option.split(PythonCore.PATH_SEPARATOR);
            path = new Object[split.length + defaultPaths];
            System.arraycopy(split, 0, path, 0, split.length);
            pathIdx = split.length;
        } else {
            path = new Object[defaultPaths];
        }
        if (!doIsolate) {
            path[pathIdx++] = getScriptPath(env, args);
        }
        path[pathIdx++] = PythonCore.getStdlibHome(env);
        path[pathIdx++] = PythonCore.getCoreHome(env) + env.getFileNameSeparator() + "modules";
        PList sysPaths = core.factory().createList(path);
        sys.setAttribute("path", sysPaths);
    }

    private static String getScriptPath(Env env, String[] args) {
        String scriptPath;
        if (args.length > 0) {
            String argv0 = args[0];
            if (argv0 != null && !argv0.startsWith("-") && !argv0.isEmpty()) {
                TruffleFile scriptFile = env.getTruffleFile(argv0);
                try {
                    scriptPath = scriptFile.getAbsoluteFile().getParent().getPath();
                } catch (SecurityException e) {
                    scriptPath = scriptFile.getParent().getPath();
                }
                if (scriptPath == null) {
                    scriptPath = ".";
                }
            } else {
                scriptPath = "";
            }
        } else {
            scriptPath = "";
        }
        return scriptPath;
    }

    static String getPythonArch() {
        String arch = System.getProperty("os.arch", "");
        if (arch.equals("amd64")) {
            // be compatible with CPython's designation
            arch = "x86_64";
        }
        return arch;
    }

    static String getPythonOSName() {
        String property = System.getProperty("os.name");
        String os = "java";
        if (property != null) {
            if (property.toLowerCase().contains("cygwin")) {
                os = "cygwin";
            } else if (property.toLowerCase().contains("linux")) {
                os = "linux";
            } else if (property.toLowerCase().contains("mac")) {
                os = "darwin";
            } else if (property.toLowerCase().contains("windows")) {
                os = "win32";
            } else if (property.toLowerCase().contains("sunos")) {
                os = "sunos";
            } else if (property.toLowerCase().contains("freebsd")) {
                os = "freebsd";
            }
        }
        return os;
    }

    @Builtin(name = "exc_info")
    @GenerateNodeFactory
    public abstract static class ExcInfoNode extends PythonBuiltinNode {

        @Specialization
        public Object run(VirtualFrame frame,
                        @Cached GetClassNode getClassNode,
                        @Cached GetCaughtExceptionNode getCaughtExceptionNode) {
            PException currentException = getCaughtExceptionNode.execute(frame);
            assert currentException != PException.NO_EXCEPTION;
            if (currentException == null) {
                return factory().createTuple(new PNone[]{PNone.NONE, PNone.NONE, PNone.NONE});
            } else {
                PBaseException exception = currentException.getExceptionObject();
                exception.reifyException();
                return factory().createTuple(new Object[]{getClassNode.execute(exception), exception, exception.getTraceback(factory())});
            }
        }

    }

    @Builtin(name = "_getframe", minNumOfPositionalArgs = 0, maxNumOfPositionalArgs = 1)
    @GenerateNodeFactory
    public abstract static class GetFrameNode extends PythonUnaryBuiltinNode {
        public static GetFrameNode create() {
            return GetFrameNodeFactory.create();
        }

        @Child private DirectCallNode call;

        @Specialization
        Object first(@SuppressWarnings("unused") PNone arg,
                        @Shared("lang") @CachedLanguage PythonLanguage lang) {
            return counted(0, lang);
        }

        /*
         * This is necessary for the time being to be compatible with the old TruffleException
         * behavior. (it only captures the frames if a CallTarget boundary is crossed)
         */
        private static final class GetStackTraceRootNode extends RootNode {
            @Child private PRaiseNode raiseNode = PRaiseNode.create();

            protected GetStackTraceRootNode(PythonLanguage language) {
                super(language);
            }

            @Override
            public Object execute(VirtualFrame frame) {
                throw raiseNode.raise(ValueError);
            }

            @Override
            public boolean isCaptureFramesForTrace() {
                return true;
            }
        }

        @Specialization
        @TruffleBoundary
        Object counted(int num,
                        @Shared("lang") @CachedLanguage PythonLanguage lang) {
            if (call == null) {
                CompilerDirectives.transferToInterpreterAndInvalidate();
                GetStackTraceRootNode rootNode = new GetStackTraceRootNode(lang);
                call = insert(Truffle.getRuntime().createDirectCallNode(Truffle.getRuntime().createCallTarget(rootNode)));
            }
            int actual = num + 1; // skip dummy frame
            try {
                @SuppressWarnings("unused")
                Object r = call.call(new Object[0]);
                // r is just assigned to make spotbugs happy
                throw raise(PythonErrorType.SystemError, "should not reach here");
            } catch (PException e) {
                PBaseException exception = e.getExceptionObject();
                exception.reifyException();
                if (actual >= exception.getStackTrace().size()) {
                    throw raiseCallStackDepth();
                }
                return exception.getPFrame(factory(), Math.max(0, actual));
            }
        }

        @Specialization(rewriteOn = ArithmeticException.class)
        Object countedLong(long num,
                        @Shared("lang") @CachedLanguage PythonLanguage lang) {
            return counted(PInt.intValueExact(num), lang);
        }

        @Specialization
        Object countedLongOvf(long num,
                        @Shared("lang") @CachedLanguage PythonLanguage lang) {
            try {
                return counted(PInt.intValueExact(num), lang);
            } catch (ArithmeticException e) {
                throw raiseCallStackDepth();
            }
        }

        @Specialization(rewriteOn = ArithmeticException.class)
        Object countedPInt(PInt num,
                        @Shared("lang") @CachedLanguage PythonLanguage lang) {
            return counted(num.intValueExact(), lang);
        }

        @Specialization
        Object countedPIntOvf(PInt num,
                        @Shared("lang") @CachedLanguage PythonLanguage lang) {
            try {
                return counted(num.intValueExact(), lang);
            } catch (ArithmeticException e) {
                throw raiseCallStackDepth();
            }
        }

        private PException raiseCallStackDepth() {
            return raise(ValueError, "call stack is not deep enough");
        }

    }

    @Builtin(name = "getfilesystemencoding", minNumOfPositionalArgs = 0)
    @GenerateNodeFactory
    public abstract static class GetFileSystemEncodingNode extends PythonBuiltinNode {
        @Specialization
        @TruffleBoundary
        protected String getFileSystemEncoding() {
            return System.getProperty("file.encoding");
        }
    }

    @Builtin(name = "getfilesystemencodeerrors", minNumOfPositionalArgs = 0)
    @GenerateNodeFactory
    public abstract static class GetFileSystemEncodeErrorsNode extends PythonBuiltinNode {
        @Specialization
        protected String getFileSystemEncoding() {
            return "surrogateescape";
        }
    }

    @Builtin(name = "intern", minNumOfPositionalArgs = 1)
    @GenerateNodeFactory
    abstract static class InternNode extends PythonBuiltinNode {
        @Specialization
        @TruffleBoundary
        String doBytes(String s) {
            return s.intern();
        }

        @Specialization
        @TruffleBoundary
        PString doBytes(PString ps) {
            String s = ps.getValue();
            return factory().createString(s.intern());
        }
    }

    @Builtin(name = "getdefaultencoding", minNumOfPositionalArgs = 0)
    @GenerateNodeFactory
    public abstract static class GetDefaultEncodingNode extends PythonBuiltinNode {
        @Specialization
        @TruffleBoundary
        protected String getFileSystemEncoding() {
            return Charset.defaultCharset().name();
        }
    }

    @Builtin(name = "getsizeof", minNumOfPositionalArgs = 1, maxNumOfPositionalArgs = 2)
    @GenerateNodeFactory
    public abstract static class GetsizeofNode extends PythonBinaryBuiltinNode {
        @Child private CastToIntegerFromIntNode castToIntNode = CastToIntegerFromIntNode.create();

        @Specialization(guards = "isNoValue(dflt)")
        protected Object doGeneric(VirtualFrame frame, Object object, @SuppressWarnings("unused") PNone dflt,
                        @Cached("createWithError()") LookupAndCallUnaryNode callSizeofNode) {
            Object result = castToIntNode.execute(callSizeofNode.executeObject(frame, object));
            return checkResult(result);
        }

        @Specialization(guards = "!isNoValue(dflt)")
        protected Object doGeneric(VirtualFrame frame, Object object, Object dflt,
                        @Cached("createWithoutError()") LookupAndCallUnaryNode callSizeofNode) {
            Object result = castToIntNode.execute(callSizeofNode.executeObject(frame, object));
            if (result == PNone.NO_VALUE) {
                return dflt;
            }
            return checkResult(result);
        }

        private Object checkResult(Object result) {
            long value = -1;
            if (result instanceof Number) {
                value = ((Number) result).longValue();
            } else if (result instanceof PInt) {
                try {
                    value = ((PInt) result).longValueExact();
                } catch (ArithmeticException e) {
                    // fall through
                }
            }
            if (value < 0) {
                throw raise(ValueError, "__sizeof__() should return >= 0");
            }
            return value;
        }

        protected LookupAndCallUnaryNode createWithError() {
            return LookupAndCallUnaryNode.create(__SIZEOF__, () -> new NoAttributeHandler() {
                @Override
                public Object execute(Object receiver) {
                    throw raise(TypeError, "Type %p doesn't define %s", receiver, __SIZEOF__);
                }
            });
        }

        protected LookupAndCallUnaryNode createWithoutError() {
            return LookupAndCallUnaryNode.create(__SIZEOF__);
        }
    }

}
