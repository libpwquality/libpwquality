/*
 * libpwquality Python bindings
 *
 * Copyright (c) Red Hat, Inc, 2011
 * Copyright (c) Tomas Mraz <tm@t8m.info>, 2011
 *
 * See the end of the file for the License Information
 */

#include <Python.h>
#include "pwquality.h"

static PyObject *PWQError;

typedef struct {
        PyObject_HEAD
        pwquality_settings_t *pwq;
} PWQSettings;

static PyObject *
pwqsettings_new(PyTypeObject *type, PyObject *args, PyObject *kwds);
static void
pwqsettings_dealloc(PWQSettings *self);
static PyObject *
pwqsettings_getint(PWQSettings *self, void *setting);
static int
pwqsettings_setint(PWQSettings *self, PyObject *value, void *setting);
static PyObject *
pwqsettings_getstr(PWQSettings *self, void *setting);
static int
pwqsettings_setstr(PWQSettings *self, PyObject *value, void *setting);
static PyObject *
read_config(PWQSettings *self, PyObject *args);
static PyObject *
set_option(PWQSettings *self, PyObject *args);
static PyObject *
generate(PWQSettings *self, PyObject *args);
static PyObject *
check(PWQSettings *self, PyObject *args);

static PyMethodDef pwqsettings_methods[] = {
        { "read_config", (PyCFunction)read_config, METH_VARARGS,
                "Read the settings from configuration file\n\nParameters:\n"
                "        cfgfilename - path to the configuration file (optional)"
        },
        { "set_option", (PyCFunction)set_option, METH_VARARGS,
                "Set option from name=value pair\n\nParameters:\n"
                "        option - string with the name=value pair"
        },
        { "generate", (PyCFunction)generate, METH_VARARGS,
                "Generate password with requested entropy\n\nParameters:\n"
                "        entropy - integer entropy bits used to generate the password"
        },
        { "check", (PyCFunction)check, METH_VARARGS,
                "Check whether the password conforms to the requirements and return password strength score"
                "\n\nParameters:\n"
                "        password - password string to be checked\n"
                "        oldpassword - old password string (or None) for additional checks (optional)\n"
                "        username - user name (or None) for additional checks (optional)"
        },
        { NULL }  /* Sentinel */
};

static PyGetSetDef pwqsettings_getseters[] = {
        { "difok",
                (getter)pwqsettings_getint, (setter)pwqsettings_setint,
                "Minimum difference from the old password",
                (void *)PWQ_SETTING_DIFF_OK
        },
        { "minlen",
                (getter)pwqsettings_getint, (setter)pwqsettings_setint,
                "Minimum length of the new password",
                (void *)PWQ_SETTING_MIN_LENGTH
        },
        { "dcredit",
                (getter)pwqsettings_getint, (setter)pwqsettings_setint,
                "Credit for or minimum of digits",
                (void *)PWQ_SETTING_DIG_CREDIT
        },
        { "ucredit",
                (getter)pwqsettings_getint, (setter)pwqsettings_setint,
                "Credit for or minimum of uppercase characters",
                (void *)PWQ_SETTING_UP_CREDIT
        },
        { "lcredit",
                (getter)pwqsettings_getint, (setter)pwqsettings_setint,
                "Credit for or minimum of lowercase characters",
                (void *)PWQ_SETTING_LOW_CREDIT
        },
        { "ocredit",
                (getter)pwqsettings_getint, (setter)pwqsettings_setint,
                "Credit for or minimum of other characters",
                (void *)PWQ_SETTING_OTH_CREDIT
        },
        { "minclass",
                (getter)pwqsettings_getint, (setter)pwqsettings_setint,
                "Minimum number of character classes",
                (void *)PWQ_SETTING_MIN_CLASS
        },
        { "maxrepeat",
                (getter)pwqsettings_getint, (setter)pwqsettings_setint,
                "Maximum repeated consecutive characters",
                (void *)PWQ_SETTING_MAX_REPEAT
        },
        { "maxclassrepeat",
                (getter)pwqsettings_getint, (setter)pwqsettings_setint,
                "Maximum consecutive characters of the same class",
                (void *)PWQ_SETTING_MAX_CLASS_REPEAT
        },
        { "gecoscheck",
                (getter)pwqsettings_getint, (setter)pwqsettings_setint,
                "Match words from the passwd GECOS field if available",
                (void *)PWQ_SETTING_GECOS_CHECK
        },
        { "badwords",
                (getter)pwqsettings_getstr, (setter)pwqsettings_setstr,
                "List of words more than 3 characters long that are forbidden",
                (void *)PWQ_SETTING_BAD_WORDS
        },
        { "dictpath",
                (getter)pwqsettings_getstr, (setter)pwqsettings_setstr,
                "Path to the cracklib dictionary",
                (void *)PWQ_SETTING_DICT_PATH
        },
        { NULL }  /* Sentinel */
};


static PyTypeObject pwqsettings_type = {
        PyObject_HEAD_INIT(NULL)
        0,                         /* ob_size */
        "pwquality.PWQSettings",   /* tp_name */
        sizeof(PWQSettings),       /* tp_basicsize */
        0,                         /* tp_itemsize */
        (destructor)pwqsettings_dealloc, /* tp_dealloc */
        0,                         /* tp_print */
        0,                         /* tp_getattr */
        0,                         /* tp_setattr */
        0,                         /* tp_compare */
        0,                         /* tp_repr */
        0,                         /* tp_as_number */
        0,                         /* tp_as_sequence */
        0,                         /* tp_as_mapping */
        0,                         /* tp_hash */
        0,                         /* tp_call */
        0,                         /* tp_str */
        0,                         /* tp_getattro */
        0,                         /* tp_setattro */
        0,                         /* tp_as_buffer */
        Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
        "PWQSettings objects - libpwquality functionality wrapper", /* tp_doc */
        0,                         /* tp_traverse */
        0,                         /* tp_clear */
        0,                         /* tp_richcompare */
        0,                         /* tp_weaklistoffset */
        0,                         /* tp_iter */
        0,                         /* tp_iternext */
        pwqsettings_methods,       /* tp_methods */
        0,                         /* tp_members */
        pwqsettings_getseters,     /* tp_getset */
        0,                         /* tp_base */
        0,                         /* tp_dict */
        0,                         /* tp_descr_get */
        0,                         /* tp_descr_set */
        0,                         /* tp_dictoffset */
        0,                         /* tp_init */
        0,                         /* tp_alloc */
        pwqsettings_new,           /* tp_new */
};

static PyMethodDef pwquality_methods[] = {
        { NULL }  /* Sentinel */
};

static PyObject *
pwqerror(int rc, void *auxerror)
{
        char buf[PWQ_MAX_ERROR_MESSAGE_LEN];
        PyObject *py_errvalue;
        const char *msg;

        msg = pwquality_strerror(buf, sizeof(buf), rc, auxerror);

        if (rc == PWQ_ERROR_MEM_ALLOC)
                return PyErr_NoMemory();

        py_errvalue = Py_BuildValue("is", rc, msg);
        if (py_errvalue == NULL)
                return NULL;

        if (rc == PWQ_ERROR_UNKNOWN_SETTING || rc == PWQ_ERROR_NON_INT_SETTING
                || rc == PWQ_ERROR_NON_STR_SETTING) {
                PyErr_SetObject(PyExc_AttributeError, py_errvalue);
        } else {
                PyErr_SetObject(PWQError, py_errvalue);
        }
        Py_DECREF(py_errvalue);
        return NULL;
}

static PyObject *
pwqsettings_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
        PWQSettings *self;

        self = (PWQSettings *)type->tp_alloc(type, 0);
        if (self) {
                self->pwq = pwquality_default_settings();
                if (self->pwq == NULL) {
                        Py_DECREF(self);
                        return PyErr_NoMemory();
                }
        }
        return (PyObject *)self;
}

static void
pwqsettings_dealloc(PWQSettings *self)
{
        pwquality_free_settings(self->pwq);
        self->ob_type->tp_free((PyObject *)self);
}

static PyObject *
pwqsettings_getint(PWQSettings *self, void *setting)
{
        int value;
        int rc;

        if ((rc = pwquality_get_int_value(self->pwq, (int)(ssize_t)setting, &value)) < 0) {
                return pwqerror(rc, NULL);
        }
        return PyInt_FromLong((long)value);
}

static int
pwqsettings_setint(PWQSettings *self, PyObject *value, void *setting)
{
        long l;
        int rc;

        l = PyInt_AsLong(value);
        if (PyErr_Occurred() == NULL) {
                if ((rc = pwquality_set_int_value(self->pwq,
                        (int)(ssize_t)setting, (int)l)) < 0) {
                        pwqerror(rc, NULL);
                        return -1;
                }
                return 0;
        }
        return -1;
}

static PyObject *
pwqsettings_getstr(PWQSettings *self, void *setting)
{
        const char *value;
        int rc;

        if ((rc = pwquality_get_str_value(self->pwq, (int)(ssize_t)setting, &value)) < 0) {
                return pwqerror(rc, NULL);
        }
        if (value == NULL) {
                Py_INCREF(Py_None);
                return Py_None;
        }
        return PyString_FromString(value);
}

static int
pwqsettings_setstr(PWQSettings *self, PyObject *value, void *setting)
{
        const char *s;
        int rc;

        if (value == (PyObject *)Py_None)
                s = NULL;
        else
                s = PyString_AsString(value);

        if (PyErr_Occurred() == NULL) {
                if ((rc = pwquality_set_str_value(self->pwq,
                        (int)(ssize_t)setting, s)) < 0) {
                        pwqerror(rc, NULL);
                        return -1;
                }
                return 0;
        }
        return -1;
}

static PyObject *
read_config(PWQSettings *self, PyObject *args)
{
        char *cfgfile = NULL;
        void *auxerror;
        int rc;

        if (!PyArg_ParseTuple(args, "|s", &cfgfile))
                return NULL;
        if ((rc = pwquality_read_config(self->pwq, cfgfile, &auxerror)) < 0) {
                return pwqerror(rc, auxerror);
        }
        Py_INCREF(Py_None);
        return Py_None;
}

static PyObject *
set_option(PWQSettings *self, PyObject *args)
{
        char *option;
        int rc;

        if (!PyArg_ParseTuple(args, "s", &option))
                return NULL;
        if ((rc = pwquality_set_option(self->pwq, option)) < 0) {
                return pwqerror(rc, NULL);
        }
        Py_INCREF(Py_None);
        return Py_None;
}

static PyObject *
generate(PWQSettings *self, PyObject *args)
{
        int entropy_bits;
        char *password;
        PyObject *passobj;
        int rc;

        if (!PyArg_ParseTuple(args, "i", &entropy_bits))
                return NULL;
        if ((rc = pwquality_generate(self->pwq, entropy_bits, &password)) < 0) {
                return pwqerror(rc, NULL);
        }

        passobj = PyString_FromString(password);
        free(password);
        return passobj;
}

static PyObject *
check(PWQSettings *self, PyObject *args)
{
        char *password;
        char *oldpassword = NULL;
        char *username = NULL;
        void *auxerror;
        int rc;

        if (!PyArg_ParseTuple(args, "s|zz", &password, &oldpassword, &username))
                return NULL;
        if ((rc = pwquality_check(self->pwq, password, oldpassword,
                                  username, &auxerror)) < 0) {
                return pwqerror(rc, auxerror);
        }

        return PyInt_FromLong((long)rc);
}

PyMODINIT_FUNC
initpwquality(void)
{
        PyObject *module;

        if (PyType_Ready(&pwqsettings_type) < 0)
                return;

        module = Py_InitModule3("pwquality", pwquality_methods,
                "Libpwquality wrapper module");
        if (module == NULL)
                return;

        PWQError = PyErr_NewExceptionWithDoc("pwquality.PWQError",
                "Standard exception thrown from PWQSettings method calls\n\n"
                "The exception value is always integer error code and string description",
                NULL, NULL);
        if (PWQError == NULL) {
                Py_DECREF(module);
                return;
        }
        Py_INCREF(PWQError);
        PyModule_AddObject(module, "PWQError", PWQError);

        Py_INCREF(&pwqsettings_type);
        PyModule_AddObject(module, "PWQSettings", (PyObject *)&pwqsettings_type);

#include "constants.c"
}

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED `AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
