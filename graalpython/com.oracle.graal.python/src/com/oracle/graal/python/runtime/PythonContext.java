/*
 * Copyright (c) 2017, 2019, Oracle and/or its affiliates.
 * Copyright (c) 2013, Regents of the University of California
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 * conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package com.oracle.graal.python.runtime;

import static com.oracle.graal.python.builtins.objects.thread.PThread.GRAALPYTHON_THREADS;
import static com.oracle.graal.python.nodes.BuiltinNames.__BUILTINS__;
import static com.oracle.graal.python.nodes.BuiltinNames.__MAIN__;
import static com.oracle.graal.python.nodes.SpecialAttributeNames.__FILE__;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

import org.graalvm.nativeimage.ImageInfo;
import org.graalvm.options.OptionValues;

import com.oracle.graal.python.PythonLanguage;
import com.oracle.graal.python.builtins.objects.PythonAbstractObject;
import com.oracle.graal.python.builtins.objects.cext.PThreadState;
import com.oracle.graal.python.builtins.objects.cext.PythonNativeClass;
import com.oracle.graal.python.builtins.objects.common.HashingStorage;
import com.oracle.graal.python.builtins.objects.dict.PDict;
import com.oracle.graal.python.builtins.objects.list.PList;
import com.oracle.graal.python.builtins.objects.module.PythonModule;
import com.oracle.graal.python.builtins.objects.str.PString;
import com.oracle.graal.python.nodes.SpecialAttributeNames;
import com.oracle.graal.python.runtime.AsyncHandler.AsyncAction;
import com.oracle.graal.python.runtime.exception.PException;
import com.oracle.truffle.api.Assumption;
import com.oracle.truffle.api.CallTarget;
import com.oracle.truffle.api.CompilerDirectives;
import com.oracle.truffle.api.CompilerDirectives.CompilationFinal;
import com.oracle.truffle.api.CompilerDirectives.TruffleBoundary;
import com.oracle.truffle.api.Truffle;
import com.oracle.truffle.api.TruffleLanguage;
import com.oracle.truffle.api.TruffleLanguage.Env;
import com.oracle.truffle.api.utilities.CyclicAssumption;

public final class PythonContext {

    private final PythonLanguage language;
    private PythonModule mainModule;
    private final PythonCore core;
    private final HashMap<Object, CallTarget> atExitHooks = new HashMap<>();
    private final HashMap<PythonNativeClass, CyclicAssumption> nativeClassStableAssumptions = new HashMap<>();
    private final AtomicLong globalId = new AtomicLong(Integer.MAX_VALUE * 2L + 4L);
    private final ThreadGroup threadGroup = new ThreadGroup(GRAALPYTHON_THREADS);

    // if set to 0 the VM will set it to whatever it likes
    private final AtomicLong pythonThreadStackSize = new AtomicLong(0);
    private final Assumption nativeObjectsAllManagedAssumption = Truffle.getRuntime().createAssumption("all C API objects are managed");

    @CompilationFinal private TruffleLanguage.Env env;

    /* corresponds to 'PyThreadState.curexc_*' */
    private PException currentException;

    /* corresponds to 'PyThreadState.exc_*' */
    private PException caughtException;

    private final ReentrantLock importLock = new ReentrantLock();
    @CompilationFinal private boolean isInitialized = false;

    @CompilationFinal private PythonModule builtinsModule;
    @CompilationFinal private PDict sysModules;

    private OutputStream out;
    private OutputStream err;
    private InputStream in;
    @CompilationFinal private Object capiLibrary = null;
    private static final Assumption singleNativeContext = Truffle.getRuntime().createAssumption("single native context assumption");
    private static final Assumption singleThreaded = Truffle.getRuntime().createAssumption("single Threaded");

    @CompilationFinal private HashingStorage.Equivalence slowPathEquivalence;

    /** The thread-local state object. */
    private ThreadLocal<PThreadState> customThreadState;

    /* native pointers for context-insensitive singletons like PNone.NONE */
    private final Object[] singletonNativePtrs = new Object[PythonLanguage.getNumberOfSpecialSingletons()];

    // The context-local resources
    private final PosixResources resources;
    private final AsyncHandler handler;

    public PythonContext(PythonLanguage language, TruffleLanguage.Env env, PythonCore core) {
        this.language = language;
        this.core = core;
        this.env = env;
        this.resources = new PosixResources();
        this.handler = new AsyncHandler(language);
        if (env == null) {
            this.in = System.in;
            this.out = System.out;
            this.err = System.err;
        } else {
            this.resources.setEnv(env);
            this.in = env.in();
            this.out = env.out();
            this.err = env.err();
        }
    }

    public ThreadGroup getThreadGroup() {
        return threadGroup;
    }

    @TruffleBoundary(allowInlining = true)
    public long getPythonThreadStackSize() {
        return pythonThreadStackSize.get();
    }

    public long getAndSetPythonsThreadStackSize(long value) {
        return pythonThreadStackSize.getAndSet(value);
    }

    @TruffleBoundary(allowInlining = true)
    public long getNextGlobalId() {
        return globalId.incrementAndGet();
    }

    public OptionValues getOptions() {
        return getEnv().getOptions();
    }

    public PythonLanguage getLanguage() {
        return language;
    }

    public ReentrantLock getImportLock() {
        return importLock;
    }

    public PDict getImportedModules() {
        return sysModules;
    }

    public PDict getSysModules() {
        return sysModules;
    }

    public PythonModule getBuiltins() {
        return builtinsModule;
    }

    public TruffleLanguage.Env getEnv() {
        return env;
    }

    public void setEnv(TruffleLanguage.Env newEnv) {
        CompilerDirectives.transferToInterpreterAndInvalidate();
        env = newEnv;
        in = env.in();
        out = env.out();
        err = env.err();
        resources.setEnv(env);
    }

    /**
     * Just for testing
     */
    public void setOut(OutputStream out) {
        this.out = out;
    }

    /**
     * Just for testing
     */
    public void setErr(OutputStream err) {
        this.err = err;
    }

    public PythonModule getMainModule() {
        return mainModule;
    }

    public PythonCore getCore() {
        return core;
    }

    public InputStream getStandardIn() {
        return in;
    }

    public OutputStream getStandardErr() {
        return err;
    }

    public OutputStream getStandardOut() {
        return out;
    }

    public void setCurrentException(PException e) {
        currentException = e;
    }

    public PException getCurrentException() {
        return currentException;
    }

    public void setCaughtException(PException e) {
        caughtException = e;
    }

    public PException getCaughtException() {
        return caughtException;
    }

    public boolean isInitialized() {
        return isInitialized;
    }

    public void initialize() {
        core.initialize(this);
        setupRuntimeInformation(false);
        core.postInitialize();
    }

    public void patch(Env newEnv) {
        setEnv(newEnv);
        setupRuntimeInformation(true);
        core.postInitialize();
    }

    /**
     * During pre-initialization, we're also loading code from the Python standard library. Since
     * some of those modules may be packages, they will have their __path__ attribute set to the
     * absolute path of the package on the build system. We use this function to patch the paths
     * during build time and after starting up from a pre-initialized context so they point to the
     * run-time package paths.
     */
    private void patchPackagePaths(String from, String to) {
        for (Object v : sysModules.getDictStorage().values()) {
            if (v instanceof PythonModule) {
                // Update module.__path__
                Object path = ((PythonModule) v).getAttribute(SpecialAttributeNames.__PATH__);
                if (path instanceof PList) {
                    Object[] paths = ((PList) path).getSequenceStorage().getCopyOfInternalArray();
                    for (int i = 0; i < paths.length; i++) {
                        Object pathElement = paths[i];
                        String strPath;
                        if (pathElement instanceof PString) {
                            strPath = ((PString) pathElement).getValue();
                        } else if (pathElement instanceof String) {
                            strPath = (String) pathElement;
                        } else {
                            continue;
                        }
                        if (strPath.startsWith(from)) {
                            paths[i] = strPath.replace(from, to);
                        }
                    }
                    ((PythonModule) v).setAttribute(SpecialAttributeNames.__PATH__, core.factory().createList(paths));
                }

                // Update module.__file__
                Object file = ((PythonModule) v).getAttribute(SpecialAttributeNames.__FILE__);
                String strFile = null;
                if (file instanceof PString) {
                    strFile = ((PString) file).getValue();
                } else if (file instanceof String) {
                    strFile = (String) file;
                }
                if (strFile != null) {
                    ((PythonModule) v).setAttribute(SpecialAttributeNames.__FILE__, strFile.replace(from, to));
                }
            }
        }
    }

    private void setupRuntimeInformation(boolean isPatching) {
        PythonModule sysModule = core.lookupBuiltinModule("sys");
        sysModules = (PDict) sysModule.getAttribute("modules");

        builtinsModule = core.lookupBuiltinModule("builtins");

        mainModule = core.factory().createPythonModule(__MAIN__);
        mainModule.setAttribute(__BUILTINS__, builtinsModule);
        mainModule.setDict(core.factory().createDictFixedStorage(mainModule));

        sysModules.setItem(__MAIN__, mainModule);

        final String stdLibPlaceholder = "!stdLibHome!";
        final String stdLibHome = PythonCore.getStdlibHome(getEnv());
        if (ImageInfo.inImageBuildtimeCode()) {
            // Patch any pre-loaded packages' paths if we're running
            // pre-initialization
            patchPackagePaths(stdLibHome, stdLibPlaceholder);
        } else if (isPatching && ImageInfo.inImageRuntimeCode()) {
            // Patch any pre-loaded packages' paths to the new stdlib home if
            // we're patching a pre-initialized context
            patchPackagePaths(stdLibPlaceholder, stdLibHome);
        }

        currentException = null;
        isInitialized = true;
    }

    public boolean capiWasLoaded() {
        return this.capiLibrary != null;
    }

    public Object getCapiLibrary() {
        return this.capiLibrary;
    }

    public void setCapiWasLoaded(Object capiLibrary) {
        this.capiLibrary = capiLibrary;
    }

    public HashingStorage.Equivalence getSlowPathEquivalence() {
        if (slowPathEquivalence == null) {
            CompilerDirectives.transferToInterpreterAndInvalidate();
            slowPathEquivalence = new HashingStorage.SlowPathEquivalence();
        }
        return slowPathEquivalence;
    }

    @TruffleBoundary
    public void registerShutdownHook(Object callable, CallTarget ct) {
        atExitHooks.put(callable, ct);
    }

    @TruffleBoundary
    public void deregisterShutdownHook(Object callable) {
        atExitHooks.remove(callable);
    }

    @TruffleBoundary
    public void runShutdownHooks() {
        handler.shutdown();
        for (CallTarget f : atExitHooks.values()) {
            f.call();
        }
    }

    @TruffleBoundary
    public PThreadState getCustomThreadState() {
        if (customThreadState == null) {
            ThreadLocal<PThreadState> threadLocal = new ThreadLocal<>();
            threadLocal.set(new PThreadState());
            customThreadState = threadLocal;
        }
        return customThreadState.get();
    }

    public void initializeMainModule(String path) {
        if (path != null) {
            mainModule.setAttribute(__FILE__, path);
        }
    }

    public static Assumption getSingleNativeContextAssumption() {
        return singleNativeContext;
    }

    public static Assumption getSingleThreadedAssumption() {
        return singleThreaded;
    }

    public Assumption getNativeObjectsAllManagedAssumption() {
        return nativeObjectsAllManagedAssumption;
    }

    public boolean isExecutableAccessAllowed() {
        return getEnv().isHostLookupAllowed() || getEnv().isNativeAccessAllowed();
    }

    public PosixResources getResources() {
        return resources;
    }

    /**
     * Trigger any pending asynchronous actions
     */
    public void triggerAsyncActions() {
        handler.triggerAsyncActions();
    }

    public void registerAsyncAction(Supplier<AsyncAction> actionSupplier) {
        handler.registerAction(actionSupplier);
    }

    @TruffleBoundary
    public CyclicAssumption getNativeClassStableAssumption(PythonNativeClass cls, boolean createOnDemand) {
        CyclicAssumption assumption = nativeClassStableAssumptions.get(cls);
        if (assumption == null && createOnDemand) {
            assumption = new CyclicAssumption("Native class " + cls + " stable");
            nativeClassStableAssumptions.put(cls, assumption);
        }
        return assumption;
    }

    public void setSingletonNativePtr(PythonAbstractObject obj, Object nativePtr) {
        assert PythonLanguage.getSingletonNativePtrIdx(obj) != -1 : "invalid special singleton object";
        assert singletonNativePtrs[PythonLanguage.getSingletonNativePtrIdx(obj)] == null;
        singletonNativePtrs[PythonLanguage.getSingletonNativePtrIdx(obj)] = nativePtr;
    }

    public Object getSingletonNativePtr(PythonAbstractObject obj) {
        int singletonNativePtrIdx = PythonLanguage.getSingletonNativePtrIdx(obj);
        if (singletonNativePtrIdx != -1) {
            return singletonNativePtrs[singletonNativePtrIdx];
        }
        return null;
    }
}
