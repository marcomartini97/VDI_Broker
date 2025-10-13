#include "vdi_status_display.h"

#include "vdi_logging.h"

#include <freerdp/freerdp.h>
#include <freerdp/update.h>

#include <winpr/image.h>

#include <algorithm>
#include <cmath>
#include <sstream>
#include <vector>

#define TAG MODULE_TAG("status_display")

// Public-domain 8x8 font by Daniel Hepper: https://github.com/dhepper/font8x8
// Adapted for use as a simple status overlay.
static const std::uint8_t kFont8x8[128][8] = {
#include "font8x8_basic.inl"

// Convert RGB components to a 32-bit BGRX color value (X is unused/alpha)
constexpr std::uint32_t make_bgrx(std::uint8_t r, std::uint8_t g, std::uint8_t b)
{
	return static_cast<std::uint32_t>(b) | 
	       (static_cast<std::uint32_t>(g) << 8) |
	       (static_cast<std::uint32_t>(r) << 16);
}

// Read a pixel from a wImage, handling different color depths and bounds checking
std::uint32_t read_pixel(const wImage* image, std::uint32_t x, std::uint32_t y)
{
	// Validate input parameters
	if (!image || !image->data || image->bytesPerPixel == 0 || 
	    image->width == 0 || image->height == 0)
	{
		return 0;
	}

	// Clamp coordinates to image bounds
	const std::uint32_t clampedX = std::min(x, image->width - 1);
	const std::uint32_t clampedY = std::min(y, image->height - 1);
	
	// Calculate pixel position in the image data
	const std::uint8_t* row = image->data + static_cast<std::size_t>(clampedY) * image->scanline;
	const std::uint8_t* pixel = row + static_cast<std::size_t>(clampedX) * image->bytesPerPixel;

	std::uint8_t r = 0, g = 0, b = 0;

	// Handle different color depths
	switch (image->bytesPerPixel)
	{
		case 1: // 8-bit grayscale
			r = g = b = pixel[0];
			break;
			
		case 2: // 16-bit (5-6-5 RGB)
		{
			const std::uint16_t value = pixel[0] | (static_cast<std::uint16_t>(pixel[1]) << 8);
			b = static_cast<std::uint8_t>((value & 0x1F) << 3);
			g = static_cast<std::uint8_t>(((value >> 5) & 0x3F) << 2);
			r = static_cast<std::uint8_t>(((value >> 11) & 0x1F) << 3);
			break;
		}
		
		default: // 24/32-bit BGR(A)
			if (image->bytesPerPixel >= 3)
			{
				b = pixel[0];
				g = pixel[1];
				r = pixel[2];
			}
			break;
	}

	return make_bgrx(r, g, b);
}

vdi::StatusDisplay::StatusDisplay() = default;

bool vdi::StatusDisplay::Initialize(freerdp_peer* peer, rdpSettings* settings,
                               const std::string& backgroundImagePath,
                               std::uint32_t fallbackColorBgrx)
{
	// Validate input parameters
	if (!peer || !settings || !peer->context || !peer->context->update)
	{
		WLog_ERR(TAG, "Invalid parameters passed to StatusDisplay::Initialize");
		return false;
	}

	// Get desktop dimensions with fallback to default resolution
	width_ = freerdp_settings_get_uint32(settings, FreeRDP_DesktopWidth);
	height_ = freerdp_settings_get_uint32(settings, FreeRDP_DesktopHeight);
	if (width_ == 0 || height_ == 0)
	{
		WLog_WARN(TAG, "Invalid desktop dimensions, falling back to 1024x768");
		width_ = 1024;
		height_ = 768;
	}

	try
	{
		// Initialize background and canvas with solid color
		const std::size_t pixelCount = static_cast<std::size_t>(width_) * height_;
		background_.assign(pixelCount, fallbackColorBgrx);
		canvas_ = background_;
		
		// Store references to peer and update context
		peer_ = peer;
		update_ = peer_->context->update;

		// Load background image if specified
		if (!backgroundImagePath.empty() && !LoadBackgroundImage(backgroundImagePath, fallbackColorBgrx))
		{
			WLog_WARN(TAG, "Failed to load background image: %s", backgroundImagePath.c_str());
		}

		// Initialize dirty region to full screen
		ResetCanvas();
		ready_ = true;
		return true;
	}
	catch (const std::exception& e)
	{
		WLog_ERR(TAG, "Failed to initialize StatusDisplay: %s", e.what());
		return false;
	}
	catch (...)
	{
		WLog_ERR(TAG, "Unknown exception in StatusDisplay::Initialize");
		return false;
	}
}

bool vdi::StatusDisplay::Ready() const
{
	return ready_;
}

void vdi::StatusDisplay::ShowMessage(const std::string& message)
{
	if (!ready_)
		return;

	lastMessage_ = message;
	ResetCanvas();
	DrawMessage(message);
	Present();
}

void vdi::StatusDisplay::ResetCanvas()
{
	// Reset canvas to background
	canvas_ = background_;
	
	// Reset dirty region to full screen or empty if invalid dimensions
	if (width_ == 0 || height_ == 0)
	{
		dirty_ = false;
		fullRefresh_ = false;
		minX_ = minY_ = 0;
		maxX_ = maxY_ = 0;
		return;
	}
	
	// Mark entire canvas as dirty
	dirty_ = true;
	fullRefresh_ = true;
	minX_ = 0;
	minY_ = 0;
	maxX_ = width_ - 1;
	maxY_ = height_ - 1;
}

void vdi::StatusDisplay::DrawMessage(const std::string& message)
{
	// Early out if message is empty or display is not ready
	if (message.empty() || !ready_)
	{
		dirty_ = false;
		fullRefresh_ = false;
		return;
	}
	
	// Mark the canvas as dirty since we'll be making changes
	dirty_ = true;

	// Calculate text layout parameters
	const int scaledGlyphWidth = kGlyphWidth * kGlyphScale;
	const int scaledGlyphHeight = kGlyphHeight * kGlyphScale;
	
	// Ensure we have at least one column, even for very small displays
	const std::size_t maxColumns = std::max<std::size_t>(
	    1, 
	    width_ / static_cast<std::uint32_t>(scaledGlyphWidth + kHorizontalSpacing)
	);

	// Split message into wrapped lines
	std::vector<std::string> lines = WrapText(message, maxColumns);
	if (lines.empty())
	{
		WLog_WARN(TAG, "Failed to wrap message text");
		return;
	}

	// Calculate width of each line in pixels
	std::vector<std::uint32_t> lineWidths;
	try {
		lineWidths.reserve(lines.size());
		for (const auto& line : lines)
		{
			const std::size_t len = line.size();
			std::uint32_t width = 0;
			
			if (len > 0)
			{
				// Calculate total width including character spacing
				width = static_cast<std::uint32_t>(len) * scaledGlyphWidth;
				if (len > 1)
				{
					width += static_cast<std::uint32_t>(len - 1) * kHorizontalSpacing;
				}
			}
			lineWidths.push_back(width);
		}
	}
	catch (const std::exception& e)
	{
		WLog_ERR(TAG, "Error calculating line widths: %s", e.what());
		return;
	}

	const std::uint32_t totalHeight =
	    static_cast<std::uint32_t>(lines.size()) * scaledGlyphHeight +
	    static_cast<std::uint32_t>(std::max<std::size_t>(0, lines.size() - 1)) *
	        static_cast<std::uint32_t>(kVerticalSpacing);
	const std::uint32_t startY =
	    (height_ > totalHeight) ? (height_ - totalHeight) / 2 : 0;

	std::uint32_t rectLeft = (width_ == 0) ? 0 : width_;
	std::uint32_t rectRight = (width_ == 0) ? 0 : 0;
	std::uint32_t rectTop = startY;
	std::uint32_t rectBottom = 0;
	if (height_ == 0)
	{
		rectBottom = 0;
	}
	else
	{
		const std::uint32_t rawBottom = startY + totalHeight;
		rectBottom = (rawBottom == 0) ? 0 : std::min<std::uint32_t>(height_, rawBottom) - 1;
	}

	std::uint32_t currentY = startY;
	for (std::size_t idx = 0; idx < lines.size(); ++idx)
	{
		const std::uint32_t lineWidth = lineWidths[idx];
		const std::uint32_t lineLeft =
		    (width_ > lineWidth) ? (width_ - lineWidth) / 2 : 0;
		std::uint32_t lineRight = lineLeft;
		if (lineWidth > 0)
		{
			lineRight = lineLeft + lineWidth - 1;
			if (width_ > 0 && lineRight >= width_)
				lineRight = width_ - 1;
		}
		else if (width_ > 0)
		{
			lineRight = std::min<std::uint32_t>(width_ - 1, lineLeft);
		}
		if (width_ == 0)
		{
			rectLeft = rectRight = 0;
		}
		else
		{
			if (lineLeft < rectLeft)
				rectLeft = lineLeft;
			if (lineRight > rectRight)
				rectRight = lineRight;
		}

		std::uint32_t lineBottom = currentY + scaledGlyphHeight - 1;
		if (height_ > 0 && lineBottom >= height_)
			lineBottom = height_ - 1;
		if (lineBottom > rectBottom)
			rectBottom = lineBottom;
		if (currentY < rectTop)
			rectTop = currentY;

		currentY += scaledGlyphHeight + kVerticalSpacing;
	}

	const std::uint32_t padding = static_cast<std::uint32_t>(kGlyphScale * 2);
	if (rectLeft > padding)
		rectLeft -= padding;
	else
		rectLeft = 0;
	if (width_ > 0)
	{
		if (rectRight + padding < width_)
			rectRight += padding;
		else
			rectRight = width_ - 1;
	}

	if (rectTop > padding)
		rectTop -= padding;
	else
		rectTop = 0;
	if (height_ > 0)
	{
		if (rectBottom + padding < height_)
			rectBottom += padding;
		else
			rectBottom = height_ - 1;
	}

	minX_ = rectLeft;
	maxX_ = (width_ == 0) ? 0 : rectRight;
	minY_ = rectTop;
	maxY_ = (height_ == 0) ? 0 : rectBottom;
	dirty_ = true;
	fullRefresh_ = true;

	currentY = startY;
	for (std::size_t idx = 0; idx < lines.size(); ++idx)
	{
		DrawLine(lines[idx], currentY);
		currentY += scaledGlyphHeight + kVerticalSpacing;
		if (currentY >= height_)
			break;
	}
	fullRefresh_ = false;
}

void vdi::StatusDisplay::DrawLine(const std::string& line, std::uint32_t startY)
{
	const int scaledGlyphWidth = kGlyphWidth * kGlyphScale;
	const int scaledGlyphHeight = kGlyphHeight * kGlyphScale;

	const std::size_t chars = line.size();
	const std::uint32_t lineWidth =
	    static_cast<std::uint32_t>(chars) * scaledGlyphWidth +
	    static_cast<std::uint32_t>(chars ? chars - 1 : 0) * static_cast<std::uint32_t>(kHorizontalSpacing);
	const std::uint32_t startX =
	    (width_ > lineWidth) ? (width_ - lineWidth) / 2 : 0;

	std::uint32_t currentX = startX;
	for (char ch : line)
	{
		if (currentX >= width_)
			break;
		DrawGlyph(ch, currentX, startY);
		currentX += scaledGlyphWidth + kHorizontalSpacing;
	}

	// Optional underline when text width exceeds canvas.
	if (lineWidth > width_)
	{
		const std::uint32_t y = std::min(height_ - 1, startY + scaledGlyphHeight + 1);
		for (std::uint32_t x = 0; x < width_; ++x)
			canvas_[static_cast<std::size_t>(y) * width_ + x] = kShadowColorBgrx;
		if (!fullRefresh_)
		{
			if (y < minY_)
				minY_ = y;
			if (y > maxY_)
				maxY_ = y;
			minX_ = 0;
			maxX_ = width_ - 1;
		}
		dirty_ = true;
	}
}

void vdi::StatusDisplay::DrawGlyph(char ch, std::uint32_t startX, std::uint32_t startY)
{
	const unsigned char index = static_cast<unsigned char>(ch);
	const std::uint8_t* glyph = kFont8x8[(index < 128) ? index : static_cast<unsigned char>('?')];
	const int scaledGlyphWidth = kGlyphWidth * kGlyphScale;
	const int scaledGlyphHeight = kGlyphHeight * kGlyphScale;

	for (int row = 0; row < kGlyphHeight; ++row)
	{
		const std::uint8_t bits = glyph[row];
		for (int col = 0; col < kGlyphWidth; ++col)
		{
			const bool set = (bits >> col) & 0x01;
			if (!set)
				continue;

			for (int dy = 0; dy < kGlyphScale; ++dy)
			{
				const std::uint32_t glyphRow =
				    static_cast<std::uint32_t>(kGlyphHeight - 1 - row);
				const std::uint32_t y =
				    startY + glyphRow * kGlyphScale + static_cast<std::uint32_t>(dy);
				if (y >= height_)
					continue;

				for (int dx = 0; dx < kGlyphScale; ++dx)
				{
					const std::uint32_t glyphCol =
					    static_cast<std::uint32_t>(kGlyphWidth - 1 - col);
					const std::uint32_t x =
					    startX + glyphCol * kGlyphScale + static_cast<std::uint32_t>(dx);
					if (x >= width_)
						continue;

					const std::size_t indexPixel = static_cast<std::size_t>(y) * width_ + x;
					canvas_[indexPixel] = kTextColorBgrx;
					if (!fullRefresh_)
					{
						if (!dirty_)
						{
							dirty_ = true;
							minX_ = maxX_ = x;
							minY_ = maxY_ = y;
						}
						else
						{
							if (x < minX_)
								minX_ = x;
							if (x > maxX_)
								maxX_ = x;
							if (y < minY_)
								minY_ = y;
							if (y > maxY_)
								maxY_ = y;
						}
					}
					else
					{
						dirty_ = true;
					}
				}
			}
		}
	}
}

void vdi::StatusDisplay::Present()
{
	if (!update_ || !peer_)
		return;
	if (!dirty_)
		return;

	const std::uint32_t destLeft = minX_;
	const std::uint32_t destTop = minY_;
	const std::uint32_t destRight = std::min(width_, maxX_ + 1);
	const std::uint32_t destBottom = std::min(height_, maxY_ + 1);
	if ((destRight <= destLeft) || (destBottom <= destTop))
	{
		dirty_ = false;
		return;
	}

	const std::uint32_t regionWidth = destRight - destLeft;
	const std::uint32_t regionHeight = destBottom - destTop;
	try
	{
		work_.resize(static_cast<std::size_t>(regionWidth) * regionHeight);
	}
	catch (...)
	{
		return;
	}

	for (std::uint32_t row = 0; row < regionHeight; ++row)
	{
		const std::uint32_t srcY = destTop + row;
		const std::size_t srcIndex = static_cast<std::size_t>(srcY) * width_ + destLeft;
		const std::size_t dstIndex = static_cast<std::size_t>(row) * regionWidth;
		std::copy_n(canvas_.begin() + srcIndex, regionWidth, work_.begin() + dstIndex);
	}

	SURFACE_BITS_COMMAND cmd{};
	cmd.cmdType = CMDTYPE_SET_SURFACE_BITS;
	cmd.destLeft = destLeft;
	cmd.destTop = destTop;
	cmd.destRight = destRight;
	cmd.destBottom = destBottom;
	cmd.bmp.bpp = 32;
	cmd.bmp.flags = 0;
	cmd.bmp.codecID = 0;
	cmd.bmp.width = static_cast<std::uint16_t>(regionWidth);
	cmd.bmp.height = static_cast<std::uint16_t>(regionHeight);
	cmd.bmp.bitmapDataLength =
	    static_cast<std::uint32_t>(work_.size() * sizeof(std::uint32_t));
	cmd.bmp.bitmapData = reinterpret_cast<BYTE*>(work_.data());
	cmd.skipCompression = TRUE;

	SURFACE_FRAME_MARKER begin{};
	begin.frameAction = SURFACECMD_FRAMEACTION_BEGIN;
	SURFACE_FRAME_MARKER end{};
	end.frameAction = SURFACECMD_FRAMEACTION_END;

	update_->SurfaceFrameMarker(update_->context, &begin);
	update_->SurfaceBits(update_->context, &cmd);
	update_->SurfaceFrameMarker(update_->context, &end);
	dirty_ = false;
	fullRefresh_ = false;
	minX_ = width_;
	minY_ = height_;
	maxX_ = 0;
	maxY_ = 0;
}

bool vdi::StatusDisplay::LoadBackgroundImage(const std::string& path, std::uint32_t fallbackColorBgrx)
{
	wImage* image = winpr_image_new();
	if (!image)
		return false;

	const int status = winpr_image_read(image, path.c_str());
	if (status < 0 || !image->data || image->width == 0 || image->height == 0 || image->scanline == 0)
	{
		VDI_LOG_WARN(TAG, "Failed to load status background image: %s", path.c_str());
		winpr_image_free(image, TRUE);
		return false;
	}

	const double scaleX = static_cast<double>(image->width) / static_cast<double>(width_);
	const double scaleY = static_cast<double>(image->height) / static_cast<double>(height_);

	for (std::uint32_t y = 0; y < height_; ++y)
	{
		const std::uint32_t srcY =
		    static_cast<std::uint32_t>(std::min<double>(image->height - 1, std::floor(y * scaleY)));
		for (std::uint32_t x = 0; x < width_; ++x)
		{
			const std::uint32_t srcX =
			    static_cast<std::uint32_t>(std::min<double>(image->width - 1, std::floor(x * scaleX)));
			const std::uint32_t color = read_pixel(image, srcX, srcY);
			background_[static_cast<std::size_t>(y) * width_ + x] = color;
		}
	}

	canvas_ = background_;
	winpr_image_free(image, TRUE);
	return true;
}

std::vector<std::string> vdi::StatusDisplay::WrapText(const std::string& text, std::size_t maxColumns)
{
	if (maxColumns == 0)
		maxColumns = 1;

	std::vector<std::string> result;
	std::istringstream linesStream(text);
	std::string paragraph;

	while (std::getline(linesStream, paragraph))
	{
		if (paragraph.empty())
		{
			result.emplace_back();
			continue;
		}

		std::istringstream wordStream(paragraph);
		std::string word;
		std::string current;

		while (wordStream >> word)
		{
			const bool needSpace = !current.empty();
			const std::size_t needed = word.size() + (needSpace ? 1u : 0u);

			if (current.size() + needed <= maxColumns)
			{
				if (needSpace)
					current.push_back(' ');
				current += word;
				continue;
			}

			if (!current.empty())
			{
				result.push_back(current);
				current.clear();
			}

			if (word.size() <= maxColumns)
			{
				current = word;
			}
			else
			{
				std::size_t start = 0;
				while (start < word.size())
				{
					const std::size_t remaining = word.size() - start;
					const std::size_t chunk = std::min(maxColumns, remaining);
					result.push_back(word.substr(start, chunk));
					start += chunk;
				}
			}
		}

		if (!current.empty())
			result.push_back(current);
	}

	if (result.empty())
		result.emplace_back();

	return result;
}

