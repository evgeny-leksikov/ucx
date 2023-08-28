#
# Copyright (C) Mellanox Technologies Ltd. 2023.  ALL RIGHTS RESERVED.
# See file LICENSE for terms.
#

urom_happy="no"

AC_ARG_WITH([urom],
            [AS_HELP_STRING([--with-urom=(DIR)],
            [Enable the use of urom service for RDMO API (default is guess).])],
            [],
            [with_urom=guess])

AS_IF([test "x$with_urom" != xno],
      [
        AS_CASE(["x$with_urom"],
                [x|xguess|xyes],
                    [
                        AC_MSG_NOTICE([UROM path not specified. Guessing ...])
                        UROM_CPPFLAGS=""
                        UROM_LDFLAGS=""
                    ],
                [x/*],
                    [
                       AC_MSG_NOTICE([UROM path is "$with_urom" ...])
                       UROM_CPPFLAGS="-I${with_urom}/include"
                       UROM_LDFLAGS="-L$with_urom/lib"
                    ],
                [AC_MSG_ERROR([Invalid UROM path "$with_urom"])])

        save_CPPFLAGS="$CPPFLAGS"
        save_LDFLAGS="$LDFLAGS"

        CPPFLAGS="$CPPFLAGS $UROM_CPPFLAGS"
        LDFLAGS="$LDFLAGS $UROM_LDFLAGS"

        urom_happy="yes"

        AC_CHECK_HEADER([urom/api/urom.h], [:], [urom_happy=no])
        AS_IF([test "x$urom_happy" = "xyes"],
              [
                 AC_CHECK_LIB([urom], [urom_get_device_list], [:], [urom_happy=no])
              ])

        AS_IF([test "x$urom_happy" != "xyes" -a "x$with_urom" != "xguess"],
              [AC_MSG_ERROR([urom requested but could not be found])])

        CPPFLAGS="$save_CPPFLAGS"
        LDFLAGS="$save_LDFLAGS"

        AS_IF([test "x$urom_happy" = "xyes"],
            [
                AC_DEFINE([HAVE_UROM], 1, [Enable RDMO support])
                AC_SUBST([UROM_CPPFLAGS])
                AC_SUBST([UROM_LDFLAGS])
                AC_SUBST([UROM_LIBS], "-lurom")
            ],
            [
                AS_IF([test "x$with_urom" != "xguess"],
                    [AC_MSG_ERROR([UROM library or header not found])],
                    [AC_MSG_WARN([Disabling support for RDMO])])
            ])
        ]

    ],
    [AC_MSG_WARN([urom was explicitly disabled])]
)

AM_CONDITIONAL([HAVE_UROM], [test "x$urom_happy" != xno])
urom_enable=$urom_happy
