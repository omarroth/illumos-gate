/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2018, Joyent, Inc.
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * Platform-Specific SMBIOS Subroutines
 *
 * The routines in this file form part of <sys/smbios_impl.h> and combine with
 * the usr/src/common/smbios code to form an in-kernel SMBIOS decoding service.
 * The SMBIOS entry point is locating by scanning a range of physical memory
 * assigned to BIOS as described in Section 2 of the DMTF SMBIOS specification.
 */

#include <sys/smbios_impl.h>
#include <sys/sysmacros.h>
#include <sys/errno.h>
#include <sys/psm.h>
#include <sys/smp_impldefs.h>

smbios_hdl_t *ksmbios;
int ksmbios_flags;

static boolean_t
smbios_validate_checksum(const void *buf, size_t len)
{
	const uint8_t *data = buf;
	size_t offset;
	uint_t sum = 0;

	for (offset = 0; offset < len; offset++)
		sum += data[offset];

	return ((sum & 0xff) == 0);
}

static boolean_t
smbios_validate_sm(const void *sm, size_t remaining,
    smbios_entry_point_t *typep)
{
	const smbios_entry_t *entry = (const smbios_entry_t *)sm;
	size_t len;

	if (remaining >= SMB3_ENTRY_EANCHORLEN &&
	    strncmp(sm, SMB3_ENTRY_EANCHOR, SMB3_ENTRY_EANCHORLEN) == 0) {
		if (remaining < sizeof (smbios_30_entry_t))
			return (B_FALSE);

		len = entry->ep30.smbe_elen;
		if (len < SMBIOS_30_ENTRY_MINLEN ||
		    len > SMBIOS_30_ENTRY_MAXLEN || len > remaining)
			return (B_FALSE);

		if (!smbios_validate_checksum(sm, len))
			return (B_FALSE);

		*typep = SMBIOS_ENTRY_POINT_30;
		return (B_TRUE);
	}

	if (remaining >= SMB_ENTRY_EANCHORLEN &&
	    strncmp(sm, SMB_ENTRY_EANCHOR, SMB_ENTRY_EANCHORLEN) == 0) {
		const size_t dmi_offset = offsetof(smbios_21_entry_t,
		    smbe_ianchor);
		const size_t dmi_len = sizeof (smbios_21_entry_t) - dmi_offset;

		if (remaining < sizeof (smbios_21_entry_t))
			return (B_FALSE);

		if (strncmp(entry->ep21.smbe_ianchor, SMB_ENTRY_IANCHOR,
		    SMB_ENTRY_IANCHORLEN) != 0)
			return (B_FALSE);

		len = entry->ep21.smbe_elen;
		if (len < SMBIOS_21_ENTRY_MINLEN ||
		    len > SMBIOS_21_ENTRY_MAXLEN || len > remaining)
			return (B_FALSE);

		if (!smbios_validate_checksum(sm, len))
			return (B_FALSE);

		if (!smbios_validate_checksum((const uint8_t *)sm + dmi_offset,
		    dmi_len))
			return (B_FALSE);

		*typep = SMBIOS_ENTRY_POINT_21;
		return (B_TRUE);
	}

	return (B_FALSE);
}

smbios_hdl_t *
smb_open_error(smbios_hdl_t *shp, int *errp, int err)
{
	if (shp != NULL)
		smbios_close(shp);

	if (errp != NULL)
		*errp = err;

	if (ksmbios == NULL)
		cmn_err(CE_CONT, "?SMBIOS not loaded (%s)", smbios_errmsg(err));

	return (NULL);
}

smbios_hdl_t *
smbios_open(const char *file, int version, int flags, int *errp)
{
	smbios_hdl_t *shp = NULL;
	const smbios_entry_t *ep;
	caddr_t staddr, stbuf, bios;
	uint64_t startaddr, startoff = 0;
	size_t bioslen;
	uint_t smbe_stlen;
	smbios_entry_point_t scan_type, ep_type;
	uint8_t smbe_major, smbe_minor;
	int err;
	const smbios_21_entry_t *smb2 = NULL;
	const smbios_30_entry_t *smb3 = NULL;

	if (file != NULL || (flags & ~SMB_O_MASK))
		return (smb_open_error(shp, errp, ESMB_INVAL));

	if ((startaddr = ddi_prop_get_int64(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "smbios-address", 0)) == 0) {
		startaddr = SMB_RANGE_START;
		bioslen = SMB_RANGE_LIMIT - SMB_RANGE_START + 1;
	} else {
		/*
		 * We have smbios address from boot loader, map a page or two.
		 */
		bioslen = MMU_PAGESIZE;
		startoff = startaddr & MMU_PAGEOFFSET;
		startaddr &= MMU_PAGEMASK;
		if (bioslen - startoff <= startoff)
			bioslen += MMU_PAGESIZE;
	}
	bios = psm_map_phys(startaddr, bioslen, PSM_PROT_READ);
	if (bios == NULL)
		return (smb_open_error(shp, errp, ESMB_MAPDEV));

	/*
	 * In case we did map one page, make sure we will not cross
	 * the end of the page.
	 */
	for (size_t off = 0; off < bioslen - startoff;
	    off += SMB_SCAN_STEP) {
		const void *p = bios + startoff + off;
		size_t left = bioslen - startoff - off;

		if (smb2 != NULL && smb3 != NULL)
			break;

		if (!smbios_validate_sm(p, left, &scan_type))
			continue;

		switch (scan_type) {
		case SMBIOS_ENTRY_POINT_21:
			if (smb2 == NULL)
				smb2 = p;
			break;
		case SMBIOS_ENTRY_POINT_30:
			if (smb3 == NULL)
				smb3 = p;
			break;
		}
	}

	if (smb2 == NULL && smb3 == NULL) {
		psm_unmap_phys(bios, bioslen);
		return (smb_open_error(shp, errp, ESMB_NOTFOUND));
	}

	/*
	 * While they're not supposed to (as per the SMBIOS 3.2 spec), some
	 * vendors end up having a newer version in one of the two entry points
	 * than the other. If we found multiple tables then we will prefer the
	 * one with the newer version. If they're equivalent, we prefer the
	 * 32-bit version. If only one is present, then we use that.
	 */
	if (smb2 != NULL && smb3 != NULL) {
		uint8_t smb2maj, smb2min, smb3maj, smb3min;

		smb2maj = smb2->smbe_major;
		smb2min = smb2->smbe_minor;
		smb3maj = smb3->smbe_major;
		smb3min = smb3->smbe_minor;

		if (smb3maj > smb2maj ||
		    (smb3maj == smb2maj && smb3min > smb2min)) {
			ep_type = SMBIOS_ENTRY_POINT_30;
			ep = (const smbios_entry_t *)smb3;
		} else {
			ep_type = SMBIOS_ENTRY_POINT_21;
			ep = (const smbios_entry_t *)smb2;
		}
	} else if (smb3 != NULL) {
		ep_type = SMBIOS_ENTRY_POINT_30;
		ep = (const smbios_entry_t *)smb3;
	} else {
		ep_type = SMBIOS_ENTRY_POINT_21;
		ep = (const smbios_entry_t *)smb2;
	}

	switch (ep_type) {
	case SMBIOS_ENTRY_POINT_21:
		smbe_major = ep->ep21.smbe_major;
		smbe_minor = ep->ep21.smbe_minor;
		smbe_stlen = ep->ep21.smbe_stlen;
		staddr = psm_map_phys(ep->ep21.smbe_staddr, smbe_stlen,
		    PSM_PROT_READ);
		break;
	case SMBIOS_ENTRY_POINT_30:
		smbe_major = ep->ep30.smbe_major;
		smbe_minor = ep->ep30.smbe_minor;
		smbe_stlen = ep->ep30.smbe_stlen;
		staddr = psm_map_phys_new(ep->ep30.smbe_staddr, smbe_stlen,
		    PSM_PROT_READ);
		break;
	default:
		psm_unmap_phys(bios, bioslen);
		return (smb_open_error(shp, errp, ESMB_VERSION));
	}

	if (staddr == NULL) {
		psm_unmap_phys(bios, bioslen);
		return (smb_open_error(shp, errp, ESMB_MAPDEV));
	}

	stbuf = smb_alloc(smbe_stlen);
	bcopy(staddr, stbuf, smbe_stlen);
	psm_unmap_phys(staddr, smbe_stlen);

	shp = smbios_bufopen(ep, stbuf, smbe_stlen, version, flags, &err);
	psm_unmap_phys(bios, bioslen);

	if (shp == NULL) {
		smb_free(stbuf, smbe_stlen);
		return (smb_open_error(shp, errp, err));
	}

	if (ksmbios == NULL) {
		cmn_err(CE_CONT, "?SMBIOS v%u.%u loaded (%u bytes)",
		    smbe_major, smbe_minor, smbe_stlen);
		if (shp->sh_flags & SMB_FL_TRUNC)
			cmn_err(CE_CONT, "?SMBIOS table is truncated");
	}

	shp->sh_flags |= SMB_FL_BUFALLOC;

	return (shp);
}

/*ARGSUSED*/
smbios_hdl_t *
smbios_fdopen(int fd, int version, int flags, int *errp)
{
	return (smb_open_error(NULL, errp, ENOTSUP));
}

/*ARGSUSED*/
int
smbios_write(smbios_hdl_t *shp, int fd)
{
	return (smb_set_errno(shp, ENOTSUP));
}
