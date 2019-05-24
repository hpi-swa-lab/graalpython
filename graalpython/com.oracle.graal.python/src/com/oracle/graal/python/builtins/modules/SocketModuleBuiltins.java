/*
 * Copyright (c) 2018, 2019, Oracle and/or its affiliates. All rights reserved.
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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

import com.oracle.graal.python.builtins.Builtin;
import com.oracle.graal.python.builtins.CoreFunctions;
import com.oracle.graal.python.builtins.PythonBuiltinClassType;
import com.oracle.graal.python.builtins.PythonBuiltins;
import com.oracle.graal.python.builtins.objects.PNone;
import com.oracle.graal.python.builtins.objects.common.SequenceStorageNodesFactory;
import com.oracle.graal.python.builtins.objects.ints.PInt;
import com.oracle.graal.python.builtins.objects.socket.PSocket;
import com.oracle.graal.python.builtins.objects.tuple.PTuple;
import com.oracle.graal.python.builtins.objects.type.LazyPythonClass;
import com.oracle.graal.python.nodes.function.PythonBuiltinBaseNode;
import com.oracle.graal.python.nodes.function.PythonBuiltinNode;
import com.oracle.graal.python.runtime.exception.PythonErrorType;
import com.oracle.graal.python.runtime.sequence.storage.SequenceStorageFactory;
import com.oracle.truffle.api.CompilerDirectives.TruffleBoundary;
import com.oracle.truffle.api.dsl.GenerateNodeFactory;
import com.oracle.truffle.api.dsl.NodeFactory;
import com.oracle.truffle.api.dsl.Specialization;
import org.graalvm.nativeimage.ImageInfo;

@CoreFunctions(defineModule = "_socket")
public class SocketModuleBuiltins extends PythonBuiltins {
    @Override
    protected List<? extends NodeFactory<? extends PythonBuiltinBaseNode>> getNodeFactories() {
        return SocketModuleBuiltinsFactory.getFactories();
    }
    private static class Service {
        int port;
        String protocol;
        public Service(int port, String protocol) {
            this.port = port;
            this.protocol = protocol;
        }
    }

    private static final int AI_PASSIVE = 1;
    private static final int AI_CANONNAME = 2;
    private static final int AI_NUMERICHOST = 4;
    //private static final int AI_MASK = (AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST);

    private static final int AI_ALL = 256;
    private static final int AI_V4MAPPED_CFG = 512;
    private static final int AI_ADDRCONFIG = 1024;
    private static final int AI_V4MAPPED = 2048;

    //private static final int AI_DEFAULT = (AI_V4MAPPED_CFG | AI_ADDRCONFIG);

    private enum IPPROTO {
        // proto constants are here: /usr/include/netinet/in.h
        IPPROTO_TCP(6),
        IPPROTO_UDP(17);
        private final int value;

        IPPROTO(int value) {
            this.value = value;
        }

        static IPPROTO resolveProto(String proto) {
            return "tcp".equals(proto) ? IPPROTO_TCP : IPPROTO_UDP;
        }
    }

    static protected Map<String, List<Service>> services;

    @TruffleBoundary
    private static Map<String, List<Service>> parseServices() {
        File services_file = new File("/etc/services");
        try {
            BufferedReader br = new BufferedReader(new FileReader(services_file));
            String line;
            Map<String, List<Service>> parsedServices = new HashMap<>();
            while ((line = br.readLine()) != null){
                if (line.startsWith("#")) {
                    continue;
                }
                line = line.replaceAll("\\s+"," ");
                if (line.startsWith(" ")) {
                    continue;
                }
                line = line.split("#")[0];
                String[] service = line.split(" ");
                if (service.length < 2) {
                    continue;
                }
                String[] portAndProtocol = service[1].split("/");
                List<Service> serviceObj = parsedServices.computeIfAbsent(service[0], k -> new LinkedList<>());
                Service newService = new Service(Integer.parseInt(portAndProtocol[0]), portAndProtocol[1]);
                serviceObj.add(newService);
                if (service.length > 2) {
                    for (int i = 2; i < service.length; i++) {
                        serviceObj = parsedServices.computeIfAbsent(service[i], k -> new LinkedList<>());
                        serviceObj.add(newService);
                    }
                }
            }
            return parsedServices;
    } catch (Exception e) {
            return new HashMap<>();
        }
    }

    static {
        if(ImageInfo.inImageBuildtimeCode()){

            services = parseServices();
        }
    }

    // socket(family=AF_INET, type=SOCK_STREAM, proto=0, fileno=None)
    @Builtin(name = "socket", minNumOfPositionalArgs = 1, parameterNames = {"cls", "family", "type", "proto", "fileno"}, constructsClass = PythonBuiltinClassType.PSocket)
    @GenerateNodeFactory
    public abstract static class SocketNode extends PythonBuiltinNode {
        @Specialization(guards = {"isNoValue(family)", "isNoValue(type)", "isNoValue(proto)", "isNoValue(fileno)"})
        Object socket(LazyPythonClass cls, @SuppressWarnings("unused") PNone family, @SuppressWarnings("unused") PNone type, @SuppressWarnings("unused") PNone proto,
                        @SuppressWarnings("unused") PNone fileno) {
            return createSocketInternal(cls, PSocket.AF_INET, PSocket.SOCK_STREAM, 0);
        }

        @Specialization(guards = {"isNoValue(type)", "isNoValue(proto)", "isNoValue(fileno)"})
        Object socket(LazyPythonClass cls, int family, @SuppressWarnings("unused") PNone type, @SuppressWarnings("unused") PNone proto, @SuppressWarnings("unused") PNone fileno) {
            return createSocketInternal(cls, family, PSocket.SOCK_STREAM, 0);
        }

        @Specialization(guards = {"isNoValue(proto)", "isNoValue(fileno)"})
        Object socket(LazyPythonClass cls, int family, int type, @SuppressWarnings("unused") PNone proto, @SuppressWarnings("unused") PNone fileno) {
            return createSocketInternal(cls, family, type, 0);
        }

        @Specialization(guards = {"isNoValue(fileno)"})
        Object socket(LazyPythonClass cls, int family, int type, int proto, @SuppressWarnings("unused") PNone fileno) {
            return createSocketInternal(cls, family, type, proto);
        }

        private Object createSocketInternal(LazyPythonClass cls, int family, int type, int proto) {
            if (getContext().getEnv().isNativeAccessAllowed()) {
                return factory().createSocket(cls, family, type, proto);
            } else {
                throw raise(PythonErrorType.OSError, "creating sockets not allowed");
            }
        }
    }

    @Builtin(name = "gethostname", minNumOfPositionalArgs = 0)
    @GenerateNodeFactory
    public abstract static class GetHostnameNode extends PythonBuiltinNode {
        @Specialization
        @TruffleBoundary
        String doGeneric() {
            try {
                return InetAddress.getLocalHost().getHostName();
            } catch (UnknownHostException e) {
                throw raise(PythonBuiltinClassType.OSError);
            }
        }
    }

    @Builtin(name = "getaddrinfo", parameterNames = {"host", "port", "family", "type", "proto", "flags"})
    @GenerateNodeFactory
    public abstract static class GetAddrInfoNode extends PythonBuiltinNode {
        @Specialization
        @TruffleBoundary
        Object getAddrInfo(String host, int port, int family, int type, int proto, PInt flags) {
            InetAddress[] adresses = resolveHost(host);
            List<Service> serviceList = new ArrayList();
            serviceList.add(new Service(port, "tcp"));
            serviceList.add(new Service(port, "udp"));
            return mergeAdressesAndServices(adresses, serviceList, proto, flags);
        }
        @Specialization
        @TruffleBoundary
        Object getAddrInfo(String host, String port, int family, int type, int proto, PInt flags) {
            if (services == null) {
                services = parseServices();
            }
            List<Service> serviceList = services.get(port);

            InetAddress[] adresses = resolveHost(host);
            return mergeAdressesAndServices(adresses, serviceList, proto, flags);
        }

        private Object mergeAdressesAndServices(InetAddress[] adresses, List<Service> serviceList, int proto, PInt flags) {
            List<Object> addressTuples = new ArrayList<>();

            for(InetAddress addr : adresses) {
                for(Service srv : serviceList) {
                    IPPROTO protocol = IPPROTO.resolveProto(srv.protocol);
                    if (proto != 0 && proto != protocol.value) {
                        continue;
                    }
                    addressTuples.add(createAddressTuple(addr, srv.port, protocol, flags));
                }
            }
            return factory().createList(addressTuples.toArray());
        }

        private PTuple createAddressTuple(InetAddress address, int port, IPPROTO proto, PInt flags) {
            int addressFamily;
            Object sockAddr;
            if (address instanceof Inet4Address) {
                addressFamily = 2;
                sockAddr = factory().createTuple(new Object[] {address.getHostAddress(), port});
            } else {
                addressFamily = 30;
                sockAddr = factory().createTuple(new Object[] {address.getHostAddress(), port, 0, 0});
            }
            String canonname = (flags.intValue() & AI_CANONNAME) == AI_CANONNAME ? address.getCanonicalHostName() : "";
            return factory().createTuple(new Object[] {addressFamily, proto == IPPROTO.IPPROTO_TCP ? 1 : 2 , proto.value, canonname, sockAddr});
        }

        InetAddress[] resolveHost(String host) {
            try {
                return InetAddress.getAllByName(host);
            } catch (UnknownHostException e) {
                throw raise(PythonBuiltinClassType.OSError);
            }
        }
    }
}
