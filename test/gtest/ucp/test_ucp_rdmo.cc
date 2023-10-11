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
    const size_t size = ucs::rand_range(4 * UCS_KBYTE);
    const size_t iter = 100;
    mem_buffer src_buf(size, UCS_MEMORY_TYPE_HOST, seed);
    mem_buffer dst_buf(size * iter, UCS_MEMORY_TYPE_HOST);
    dst_buf.memset(0);
    mem_buffer off_buf(sizeof(void*), UCS_MEMORY_TYPE_HOST);
    off_buf.memset(0);

    ucp_mem_h off_memh  = get_memh(receiver(), off_buf);
    ucp_rkey_h off_rkey = get_rkey(sender().ep(), receiver(), off_memh);

    ucp_mem_h dst_memh  = get_memh(receiver(), dst_buf);
    ucp_rkey_h dst_rkey = get_rkey(sender().ep(), receiver(), dst_memh);

    /* post the operations */
    UCS_TEST_MESSAGE << "size: " << size << " dst_buf: " << dst_buf.ptr();
    for (size_t i = 0; i < iter; ++i) {
        ucs_status_ptr_t append_r = ucp_rdmo_append_nbx(
                sender().ep(), src_buf.ptr(), src_buf.size(),
                (uint64_t)off_buf.ptr(), off_rkey,
                (uint64_t)dst_buf.ptr(), dst_rkey);
        if (UCS_PTR_IS_PTR(append_r)) {
            ucp_request_free(append_r);
        } else {
            ASSERT_EQ(NULL, append_r);
        }
    }

    void *flush_r = sender().flush_ep_nb();
    ucs_status_t status = request_wait(flush_r);
    ASSERT_UCS_OK(status);
    ASSERT_EQ(dst_buf.size(), *(uintptr_t *)off_buf.ptr());

    /* validate */
    //dst_buf.pattern_check(seed);
    for (size_t i = 0; i < iter; ++i) {
        mem_buffer::pattern_check((char*)dst_buf.ptr() + (i * size), size,
                                  seed, src_buf.ptr());
    }

    /* free */
    ucp_rkey_destroy(dst_rkey);
    ucp_mem_unmap(receiver().ucph(), dst_memh);

    ucp_rkey_destroy(off_rkey);
    ucp_mem_unmap(receiver().ucph(), off_memh);
}

UCP_INSTANTIATE_TEST_CASE_TLS(test_ucp_rdmo, all, "all")
