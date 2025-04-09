namespace CommonLayer.DtoModells
{
    public class AdminBoardDto
    {
        public Guid CurrentUserGuid { get; set; }
        public IEnumerable<UserDto> Users { get; set; }
    }
}
