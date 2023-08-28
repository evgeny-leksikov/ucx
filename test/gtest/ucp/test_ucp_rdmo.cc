/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2023. ALL RIGHTS RESERVED.
 *
 */

#include <common/test.h>

#include "ucp_test.h"

class test_ucp_rdmo : public ucp_test {
    public:
    static void get_test_variants(variant_vec_t &variants);

    virtual void init();
};


void test_ucp_rdmo::get_test_variants(variant_vec_t &variants)
{
    add_variant_with_value(variants, UCP_FEATURE_RDMO, 0, "dflt");
}

void test_ucp_rdmo::init()
{
    ucp_test::init();
    sender().connect(&receiver(), get_ep_params());
}

UCS_TEST_P(test_ucp_rdmo, init)
{
}

UCP_INSTANTIATE_TEST_CASE(test_ucp_rdmo);
