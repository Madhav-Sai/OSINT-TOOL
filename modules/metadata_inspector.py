import io
import json
import struct
import re
from math import gcd
import streamlit as st

# Risky metadata fields that may expose sensitive info
RISKY_FIELDS = {
    "gps", "gpslatitude", "gpslongitude", "gpsaltitude", "gpsposition",
    "latitude", "longitude", "location", "geolocation",
    "author", "creator", "producer", "owner", "lastmodifiedby",
    "software", "tool", "application", "appversion",
    "serialnumber", "devicemanufacturer", "model", "make",
    "createdate", "modifydate", "datetimeoriginal",
    "comment", "description", "subject", "usercomment",
    "hostname", "ipaddress", "computer",
}


def _is_risky(key: str) -> bool:
    k = key.lower().replace(" ", "").replace("-", "").replace("_", "")
    return any(r in k for r in RISKY_FIELDS)


def extract_image_metadata(data: bytes, filename: str) -> dict:
    try:
        from PIL import Image, IptcImagePlugin
        from PIL.ExifTags import TAGS, GPSTAGS
        import io as _io

        img = Image.open(_io.BytesIO(data))

        # --- Basic image info ---
        meta = {
            "Format": img.format,
            "Mode": img.mode,
            "Size": f"{img.size[0]} × {img.size[1]} px",
            "Width_px": str(img.size[0]),
            "Height_px": str(img.size[1]),
        }

        # Megapixels
        mp = (img.size[0] * img.size[1]) / 1_000_000
        meta["Megapixels"] = f"{mp:.2f} MP"

        # Aspect ratio
        g = gcd(img.size[0], img.size[1])
        meta["AspectRatio"] = f"{img.size[0] // g}:{img.size[1] // g}"

        # Frame count (animated GIF/WebP)
        try:
            meta["FrameCount"] = str(getattr(img, "n_frames", 1))
        except Exception:
            pass

        # DPI / resolution
        if hasattr(img, "info"):
            dpi = img.info.get("dpi")
            if dpi:
                meta["DPI"] = f"{dpi[0]:.0f} × {dpi[1]:.0f}"
            jfif_density = img.info.get("jfif_density")
            if jfif_density:
                meta["JFIF_Density"] = f"{jfif_density[0]} × {jfif_density[1]}"
            jfif_unit = img.info.get("jfif_unit")
            if jfif_unit is not None:
                meta["JFIF_DensityUnit"] = {0: "No units", 1: "DPI", 2: "DPCM"}.get(jfif_unit, str(jfif_unit))

        # Color depth
        mode_bits = {
            "1": "1-bit (B&W)", "L": "8-bit grayscale", "P": "8-bit palette",
            "RGB": "24-bit", "RGBA": "32-bit", "CMYK": "32-bit CMYK",
            "YCbCr": "24-bit YCbCr", "LAB": "24-bit L*a*b*",
            "HSV": "24-bit HSV", "I": "32-bit int", "F": "32-bit float",
            "LA": "16-bit grayscale+alpha", "I;16": "16-bit", "I;16B": "16-bit BE",
        }
        meta["ColorDepth"] = mode_bits.get(img.mode, img.mode)

        # ICC / color profile
        icc = img.info.get("icc_profile")
        if icc:
            meta["ICC_ProfileSize_bytes"] = str(len(icc))
            try:
                if len(icc) > 132:
                    tag_count = struct.unpack(">I", icc[128:132])[0]
                    for i in range(min(tag_count, 30)):
                        offset = 132 + i * 12
                        if offset + 12 > len(icc):
                            break
                        sig = icc[offset:offset+4].decode("latin-1")
                        tag_offset = struct.unpack(">I", icc[offset+4:offset+8])[0]
                        tag_size = struct.unpack(">I", icc[offset+8:offset+12])[0]
                        if sig == "desc" and tag_offset + tag_size <= len(icc):
                            desc_data = icc[tag_offset:tag_offset+tag_size]
                            if desc_data[:4] == b"mluc":
                                try:
                                    s = desc_data[28:].decode("utf-16-be").strip("\x00")
                                    if s:
                                        meta["ICC_ProfileName"] = s[:80]
                                except Exception:
                                    pass
                            elif desc_data[:4] == b"desc":
                                try:
                                    length = struct.unpack(">I", desc_data[8:12])[0]
                                    s = desc_data[12:12+length].decode("ascii", errors="replace").strip("\x00")
                                    if s:
                                        meta["ICC_ProfileName"] = s[:80]
                                except Exception:
                                    pass
                        if sig == "wtpt" and tag_offset + tag_size <= len(icc):
                            wp_data = icc[tag_offset:tag_offset+tag_size]
                            if len(wp_data) >= 20:
                                x = struct.unpack(">i", wp_data[8:12])[0] / 65536.0
                                y = struct.unpack(">i", wp_data[12:16])[0] / 65536.0
                                z = struct.unpack(">i", wp_data[16:20])[0] / 65536.0
                                meta["ICC_WhitePoint_XYZ"] = f"X={x:.4f} Y={y:.4f} Z={z:.4f}"
            except Exception:
                pass
            if len(icc) >= 128:
                try:
                    device_class = icc[12:16].decode("latin-1").strip()
                    cs = icc[16:20].decode("latin-1").strip()
                    profile_class_map = {
                        "scnr": "Scanner", "mntr": "Monitor", "prtr": "Printer",
                        "link": "DeviceLink", "spac": "ColorSpace",
                        "abst": "Abstract", "nmcl": "NamedColor",
                    }
                    colorspace_map = {
                        "RGB ": "RGB", "CMYK": "CMYK", "GRAY": "Grayscale",
                        "Lab ": "CIE L*a*b*", "XYZ ": "XYZ",
                        "YCbr": "YCbCr", "Luv ": "CIE Luv", "Yxy ": "Yxy",
                    }
                    meta["ICC_DeviceClass"] = profile_class_map.get(device_class, device_class)
                    meta["ICC_ColorSpace"] = colorspace_map.get(cs, cs)
                    rendering_intent = struct.unpack(">I", icc[64:68])[0]
                    intent_map = {
                        0: "Perceptual", 1: "Relative Colorimetric",
                        2: "Saturation", 3: "Absolute Colorimetric",
                    }
                    meta["ICC_RenderingIntent"] = intent_map.get(rendering_intent, str(rendering_intent))
                except Exception:
                    pass

        # XMP metadata
        xmp_raw = img.info.get("XML:com.adobe.xmp") or img.info.get("xmp")
        if xmp_raw:
            xmp_str = xmp_raw.decode("utf-8", errors="replace") if isinstance(xmp_raw, bytes) else xmp_raw
            meta["XMP_Present"] = "Yes"
            meta["XMP_Size_bytes"] = str(len(xmp_str))
            xmp_fields = {
                "xmp:CreatorTool": "XMP_CreatorTool",
                "xmp:CreateDate": "XMP_CreateDate",
                "xmp:ModifyDate": "XMP_ModifyDate",
                "xmp:MetadataDate": "XMP_MetadataDate",
                "xmp:Rating": "XMP_Rating",
                "xmpMM:DocumentID": "XMP_DocumentID",
                "xmpMM:InstanceID": "XMP_InstanceID",
                "xmpMM:OriginalDocumentID": "XMP_OriginalDocumentID",
                "dc:creator": "XMP_Creator",
                "dc:description": "XMP_Description",
                "dc:rights": "XMP_Rights",
                "dc:subject": "XMP_Subject",
                "dc:title": "XMP_Title",
                "photoshop:ColorMode": "XMP_ColorMode",
                "photoshop:ICCProfile": "XMP_ICCProfile",
                "photoshop:DateCreated": "XMP_DateCreated",
                "photoshop:Credit": "XMP_Credit",
                "photoshop:Source": "XMP_Source",
                "Iptc4xmpCore:Location": "XMP_Location",
                "Iptc4xmpCore:CountryCode": "XMP_CountryCode",
                "exifEX:LensModel": "XMP_LensModel",
                "exifEX:LensMake": "XMP_LensMake",
            }
            for xml_key, out_key in xmp_fields.items():
                patterns = [
                    rf'<{re.escape(xml_key)}[^>]*>([^<]{{1,200}})</{re.escape(xml_key)}>',
                    rf'{re.escape(xml_key)}="([^"{{1,200}})"',
                ]
                for pat in patterns:
                    m = re.search(pat, xmp_str)
                    if m:
                        val = m.group(1).strip()
                        if val and not val.startswith("<"):
                            meta[out_key] = val[:200]
                        break

        # IPTC metadata
        try:
            iptc = IptcImagePlugin.getiptcinfo(img)
            if iptc:
                iptc_tag_names = {
                    (1, 90): "IPTC_CodedCharacterSet",
                    (2, 5): "IPTC_ObjectName",
                    (2, 25): "IPTC_Keywords",
                    (2, 40): "IPTC_SpecialInstructions",
                    (2, 55): "IPTC_DateCreated",
                    (2, 60): "IPTC_TimeCreated",
                    (2, 65): "IPTC_OriginatingProgram",
                    (2, 70): "IPTC_ProgramVersion",
                    (2, 80): "IPTC_Byline",
                    (2, 85): "IPTC_BylineTitle",
                    (2, 90): "IPTC_City",
                    (2, 92): "IPTC_Sublocation",
                    (2, 95): "IPTC_ProvinceState",
                    (2, 100): "IPTC_CountryCode",
                    (2, 101): "IPTC_CountryName",
                    (2, 105): "IPTC_Headline",
                    (2, 110): "IPTC_Credit",
                    (2, 115): "IPTC_Source",
                    (2, 116): "IPTC_CopyrightNotice",
                    (2, 120): "IPTC_Caption",
                    (2, 122): "IPTC_CaptionWriter",
                }
                for tag_key, val in iptc.items():
                    label = iptc_tag_names.get(tag_key, f"IPTC_{tag_key[0]}_{tag_key[1]}")
                    if isinstance(val, list):
                        decoded = [
                            v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)
                            for v in val
                        ]
                        meta[label] = "; ".join(decoded)[:300]
                    elif isinstance(val, bytes):
                        meta[label] = val.decode("utf-8", errors="replace")[:300]
                    else:
                        meta[label] = str(val)[:300]
        except Exception:
            pass

        # Full EXIF via legacy _getexif()
        try:
            exif_data = img._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, f"EXIF_0x{tag_id:04X}")
                    if tag == "GPSInfo" and isinstance(value, dict):
                        for gtag_id, gval in value.items():
                            gtag = GPSTAGS.get(gtag_id, f"GPS_0x{gtag_id:02X}")
                            meta[f"GPS.{gtag}"] = str(gval)[:200]
                        # Decode decimal GPS coordinates
                        try:
                            def _to_decimal(dms, ref):
                                d, m, s = dms
                                dec = float(d) + float(m) / 60 + float(s) / 3600
                                if ref in ("S", "W"):
                                    dec = -dec
                                return round(dec, 6)
                            lat = _to_decimal(value[2], value[1])
                            lon = _to_decimal(value[4], value[3])
                            meta["GPS.LatitudeDecimal"] = str(lat)
                            meta["GPS.LongitudeDecimal"] = str(lon)
                            meta["GPS.MapsLink"] = f"https://maps.google.com/?q={lat},{lon}"
                        except Exception:
                            pass
                    else:
                        str_val = str(value)
                        if len(str_val) > 300 or (isinstance(value, bytes) and len(value) > 64):
                            meta[f"{tag}_size_bytes"] = str(
                                len(value) if isinstance(value, (bytes, bytearray)) else len(str_val)
                            )
                        else:
                            meta[tag] = str_val[:300]
        except Exception:
            pass

        # Extended EXIF via newer getexif() IFD API (Pillow 6+)
        try:
            exif_obj = img.getexif()
            if exif_obj:
                ifd_map = {
                    0x8769: "ExifIFD",
                    0x8825: "GPSIFD",
                    0xA005: "InteropIFD",
                }
                for ifd_tag, ifd_name in ifd_map.items():
                    try:
                        ifd = exif_obj.get_ifd(ifd_tag)
                        for k, v in ifd.items():
                            label = TAGS.get(k, GPSTAGS.get(k, f"{ifd_name}_0x{k:04X}"))
                            str_val = str(v)
                            if len(str_val) <= 300 and not (isinstance(v, bytes) and len(v) > 64):
                                full_key = f"{ifd_name}.{label}"
                                if full_key not in meta:
                                    meta[full_key] = str_val
                    except Exception:
                        pass
        except Exception:
            pass

        # PNG text chunks
        if img.format == "PNG":
            for k, v in img.info.items():
                if k not in ("dpi", "icc_profile", "XML:com.adobe.xmp", "xmp") and isinstance(v, str) and v:
                    meta[f"PNG.{k}"] = v[:300]

        # GIF version
        if img.format == "GIF":
            meta["GIF_Version"] = img.info.get("version", "unknown")

        # JPEG quantization tables
        if hasattr(img, "quantization") and img.quantization:
            meta["JPEG_QuantizationTables"] = str(len(img.quantization))

        # JPEG APP markers
        if img.format == "JPEG" and hasattr(img, "applist"):
            markers = [
                seg[0] for seg in img.applist
            ]
            meta["JPEG_AppMarkers"] = ", ".join(markers)

        # Photoshop block size
        for key in ("photoshop", "adobe", "Adobe"):
            ps_data = img.info.get(key)
            if ps_data and isinstance(ps_data, (bytes, bytearray)):
                meta["Photoshop_block_size_bytes"] = str(len(ps_data))
                break

        return meta

    except Exception as e:
        return {"Error": str(e)}


def extract_pdf_metadata(data: bytes) -> dict:
    try:
        from pypdf import PdfReader
        import io as _io
        reader = PdfReader(_io.BytesIO(data))
        meta = {}
        if reader.metadata:
            for k, v in reader.metadata.items():
                clean_key = k.lstrip("/")
                meta[clean_key] = str(v)[:300]
        meta["Pages"] = str(len(reader.pages))
        return meta
    except ImportError:
        return {"Error": "pypdf not installed. Run: pip install pypdf"}
    except Exception as e:
        return {"Error": str(e)}


def extract_docx_metadata(data: bytes) -> dict:
    try:
        from docx import Document
        import io as _io
        doc = Document(_io.BytesIO(data))
        cp = doc.core_properties
        return {
            "Author":             str(cp.author or ""),
            "Last Modified By":   str(cp.last_modified_by or ""),
            "Created":            str(cp.created or ""),
            "Modified":           str(cp.modified or ""),
            "Title":              str(cp.title or ""),
            "Subject":            str(cp.subject or ""),
            "Description":        str(cp.description or ""),
            "Keywords":           str(cp.keywords or ""),
            "Category":           str(cp.category or ""),
            "Version":            str(cp.version or ""),
            "Revision":           str(cp.revision or ""),
        }
    except ImportError:
        return {"Error": "python-docx not installed. Run: pip install python-docx"}
    except Exception as e:
        return {"Error": str(e)}


def extract_audio_video_metadata(data: bytes, filename: str) -> dict:
    try:
        import mutagen
        import io as _io
        f = mutagen.File(_io.BytesIO(data), filename=filename)
        if f is None:
            return {"Error": "Unsupported audio/video format"}
        meta = {}
        for k, v in f.items():
            meta[str(k)] = str(v)[:300]
        if hasattr(f, "info"):
            info = f.info
            for attr in ("length", "bitrate", "sample_rate", "channels", "codec"):
                if hasattr(info, attr):
                    meta[attr.capitalize()] = str(getattr(info, attr))
        return meta
    except ImportError:
        return {"Error": "mutagen not installed. Run: pip install mutagen"}
    except Exception as e:
        return {"Error": str(e)}


def _render_metadata_table(meta: dict):
    if not meta:
        st.info("ℹ️ No metadata found.")
        return

    risky_fields = {k: v for k, v in meta.items() if _is_risky(k) and v}
    normal_fields = {k: v for k, v in meta.items() if not _is_risky(k) and v}

    if risky_fields:
        st.markdown(
            f"<div style='background:rgba(248,113,113,0.1);border:1px solid #F87171;"
            f"border-radius:8px;padding:10px 14px;margin-bottom:12px;'>"
            f"⚠️ <b style='color:#F87171;'>{len(risky_fields)} sensitive field(s) detected</b> "
            f"— these may expose private information</div>",
            unsafe_allow_html=True
        )

    rows = ""
    for k, v in sorted(risky_fields.items()):
        rows += (f"<tr class='meta-risky-row'>"
                 f"<td><span class='meta-risky'>⚠️ {k}</span></td>"
                 f"<td><span class='meta-risky'>{v}</span></td></tr>")
    for k, v in sorted(normal_fields.items()):
        rows += f"<tr><td>{k}</td><td>{v}</td></tr>"

    st.markdown(f"""
    <table class="meta-table">
        <thead><tr><th>Field</th><th>Value</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>
    """, unsafe_allow_html=True)

    st.download_button(
        label="⬇️ Download Full Report (JSON)",
        data=json.dumps(meta, indent=2),
        file_name="metadata_report.json",
        mime="application/json",
        use_container_width=True
    )


def render_metadata_inspector():
    st.subheader("Metadata Inspector")
    st.markdown(
        "Extract hidden metadata from files — images, documents, audio, and video. "
        "Reveals creation info, author, device, GPS, and other sensitive data."
    )

    uploaded = st.file_uploader(
        "Upload a file to inspect",
        type=["jpg", "jpeg", "png", "gif", "webp", "tiff", "bmp",
              "pdf", "docx", "doc",
              "mp3", "mp4", "wav", "flac", "ogg", "m4a", "mov", "avi", "mkv"],
        key="meta_file_upload",
        help="Supports images, PDFs, Word docs, and audio/video files"
    )

    if uploaded is not None:
        data = uploaded.read()
        fname = uploaded.name.lower()

        st.markdown(f"""
        <div class="card">
            <b>📄 File:</b> {uploaded.name} &nbsp;
            <b>Size:</b> {len(data):,} bytes
        </div>
        """, unsafe_allow_html=True)

        with st.spinner("Extracting metadata…"):
            if fname.endswith((".jpg", ".jpeg", ".png", ".gif", ".webp", ".tiff", ".bmp")):
                meta = extract_image_metadata(data, fname)
                file_type = "Image"
            elif fname.endswith(".pdf"):
                meta = extract_pdf_metadata(data)
                file_type = "PDF"
            elif fname.endswith((".docx", ".doc")):
                meta = extract_docx_metadata(data)
                file_type = "Document"
            elif fname.endswith((".mp3", ".mp4", ".wav", ".flac", ".ogg", ".m4a", ".mov", ".avi", ".mkv")):
                meta = extract_audio_video_metadata(data, fname)
                file_type = "Audio/Video"
            else:
                meta = {"Error": "Unsupported file type"}
                file_type = "Unknown"

        st.markdown(f"**Metadata for {file_type} file:**")
        _render_metadata_table(meta)
    else:
        st.markdown("""
        <div style='color:#78716C;font-size:0.9rem;line-height:1.8;padding:16px 0;'>
        📋 <b style='color:#A8A29E;'>What this tool reveals:</b><br>
        📷 <b>Images</b> — Camera model, GPS coordinates, capture date, software<br>
        📄 <b>PDFs</b> — Author, creator software, modification history<br>
        📝 <b>Word Docs</b> — Author, last edited by, revision history<br>
        🎵 <b>Audio/Video</b> — Encoder, duration, bitrate, tags
        </div>
        """, unsafe_allow_html=True)