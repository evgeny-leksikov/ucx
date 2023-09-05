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

    ucp_mem_h get_memh(entity &entity, mem_buffer &buf);
    ucp_rkey_h get_rkey(ucp_ep_h ep, entity &dst_entity, ucp_mem_h memh);
};

ucp_mem_h test_ucp_rdmo::get_memh(entity &entity, mem_buffer &buf)
{
    ucp_mem_map_params_t params;

    memset(&params, 0, sizeof(params));
    params.field_mask = UCP_MEM_MAP_PARAM_FIELD_ADDRESS |
                        UCP_MEM_MAP_PARAM_FIELD_LENGTH;
    params.address    = buf.ptr();
    params.length     = buf.size();

    ucp_mem_h memh;
    ucs_status_t status = ucp_mem_map(entity.ucph(), &params, &memh);
    ASSERT_UCS_OK(status);
    return memh;
}

ucp_rkey_h test_ucp_rdmo::get_rkey(ucp_ep_h ep, entity &dst_entity,
                                   ucp_mem_h memh)
{
    ucs_status_t status;

    void *rkey_buffer;
    size_t rkey_buffer_size;
    status = ucp_rkey_pack(dst_entity.ucph(), memh, &rkey_buffer,
                           &rkey_buffer_size);
    ASSERT_UCS_OK(status);

    ucp_rkey_h rkey;
    status = ucp_ep_rkey_unpack(ep, rkey_buffer, &rkey);
    ASSERT_UCS_OK(status);
    ucp_rkey_buffer_release(rkey_buffer);
    return rkey;
}

void test_ucp_rdmo::get_test_variants(variant_vec_t &variants)
{
    add_variant_with_value(variants, UCP_FEATURE_RDMO, 0, "dflt");
}

void test_ucp_rdmo::init()
{
    ucp_test::init();
    sender().connect(&receiver(), get_ep_params());
}

UCS_TEST_P(test_ucp_rdmo, init_fini)
{
    /* simplest test of init and finalize */
}

UCS_TEST_P(test_ucp_rdmo, basic)
{
    const uint64_t seed(0xbadc0ffe);
    mem_buffer src_buf(4 * UCS_KBYTE, UCS_MEMORY_TYPE_HOST, seed);
    mem_buffer dst_buf(4 * UCS_KBYTE, UCS_MEMORY_TYPE_HOST);
    mem_buffer ptr_buf(sizeof(void*), UCS_MEMORY_TYPE_HOST);
    memcpy(ptr_buf.ptr(), dst_buf.ptr_p(), ptr_buf.size());

//    ucp_mem_h src_memh = get_memh(sender(),   src_buf);
    ucp_mem_h ptr_memh = get_memh(receiver(), ptr_buf);
    ucp_mem_h dst_memh = get_memh(receiver(), dst_buf);

    /* post the operation */
    ucs_status_ptr_t r = ucp_rdmo_append_nbx(
            sender().ep(), src_buf.ptr(), src_buf.size(),
            (uint64_t)ptr_buf.ptr(), get_rkey(sender().ep(), receiver(), ptr_memh),
            get_rkey(sender().ep(), receiver(), dst_memh));

    /* wait for local completion */
    ucs_status_t status = request_wait(r);
    ASSERT_UCS_OK(status);

    /* wait for remote completion */
    uintptr_t *ptr_val = (uintptr_t *)ptr_buf.ptr();
    uintptr_t expected = (uintptr_t)UCS_PTR_BYTE_OFFSET(dst_buf.ptr(),
                                                        dst_buf.size());
    wait_for_value(ptr_val, expected);

    /* validate */
    dst_buf.pattern_check(seed);
}

UCP_INSTANTIATE_TEST_CASE_TLS(test_ucp_rdmo, all, "all")
