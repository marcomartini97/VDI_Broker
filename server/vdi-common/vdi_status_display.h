#pragma once

#include <freerdp/peer.h>
#include <freerdp/settings.h>

#include <cstdint>
#include <string>
#include <vector>

namespace vdi
{

class StatusDisplay
{
public:
	StatusDisplay();

	bool Initialize(freerdp_peer* peer, rdpSettings* settings, const std::string& backgroundImagePath,
	                std::uint32_t fallbackColorBgrx);
	bool Ready() const;

	void ShowMessage(const std::string& message);

private:
	bool LoadBackgroundImage(const std::string& path, std::uint32_t fallbackColorBgrx);
	void ResetCanvas();
	void DrawMessage(const std::string& message);
	void DrawLine(const std::string& line, std::uint32_t startY);
	void DrawGlyph(char ch, std::uint32_t startX, std::uint32_t startY);
	void Present();

	static std::vector<std::string> WrapText(const std::string& text, std::size_t maxColumns);

	freerdp_peer* peer_ = nullptr;
	rdpUpdate* update_ = nullptr;
	std::uint32_t width_ = 0;
	std::uint32_t height_ = 0;
	std::vector<std::uint32_t> background_;
	std::vector<std::uint32_t> canvas_;
	std::vector<std::uint32_t> work_;
	bool dirty_ = false;
	bool fullRefresh_ = false;
	bool ready_ = false;
	std::string lastMessage_;
	std::uint32_t minX_ = 0;
	std::uint32_t minY_ = 0;
	std::uint32_t maxX_ = 0;
	std::uint32_t maxY_ = 0;

	static constexpr std::uint32_t kTextColorBgrx = 0x00FFFFFFu;
	static constexpr std::uint32_t kShadowColorBgrx = 0x00202020u;
	static constexpr int kGlyphWidth = 8;
	static constexpr int kGlyphHeight = 8;
	static constexpr int kGlyphScale = 2;
	static constexpr int kHorizontalSpacing = 2;
	static constexpr int kVerticalSpacing = 4;
};

} // namespace vdi
